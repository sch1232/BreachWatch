from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import jwt
import httpx
import hashlib

from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker

from passlib.context import CryptContext

# --- Database setup ---

SQLALCHEMY_DATABASE_URL = "sqlite:///./breachwatch.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)
    input = Column(String)
    result = Column(String)
    time = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- Config ---

SECRET_KEY = "uY4rPq2L7xZ9dsmB3Vte8XjHwK0nCfNRgxDT5QzWiJafvMO1bHGElSUyopIk6WnR"
ALGORITHM = "HS256"

DEHASHED_API_KEY = "8138d9c215mshff9fd1be75d06f1p16ea48jsn7d02a1fe626d"  # Replace with actual key

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Schemas ---

class UserCreate(BaseModel):
    email: str
    password: str

class CheckInput(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None

# --- Utility Functions ---

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed: str) -> bool:
    return pwd_context.verify(plain_password, hashed)

def create_token(email: str):
    payload = {"email": email, "exp": datetime.utcnow() + timedelta(hours=12)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["email"]
    except:
        return None

# --- Dependencies and auth ---

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    try:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authorization schema")
    except:
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    email = verify_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return email

# --- DeHashed Email Breach Checker ---

async def check_dehashed_email(email: str) -> bool:
    cleaned = (email or "").strip()
    if not cleaned:
        return False
    url = f"https://api.dehashed.com/search?query=email:{cleaned}"
    headers = {
        "Authorization": f"Bearer {DEHASHED_API_KEY}"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entries", [])
            return len(entries) > 0
        elif resp.status_code == 404:
            return False
        else:
            return False

# --- HIBP Passwords API using k-anonymity (no API key needed) ---

async def check_hibp_password(password: str) -> bool:
    text = (password or "")
    if not text:
        return False
    sha1 = hashlib.sha1(text.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            return False
        suffixes = resp.text.splitlines()
        for line in suffixes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return True
        return False

# --- Routes ---

@app.post("/api/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pw = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_pw)
    db.add(db_user)
    db.flush()
    db.commit()
    return {"status": "success"}

@app.post("/api/login")
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user.email)
    return {"access_token": token}

@app.post("/api/check-email")
async def check_email(input: CheckInput, email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    if not input.email or not input.email.strip():
        raise HTTPException(status_code=400, detail="Email is required")
    found = await check_dehashed_email(input.email.strip())
    result_text = "Breach found" if found else "Safe"
    history_entry = History(type="Email", input=input.email.strip(), result=result_text, time=datetime.utcnow())
    db.add(history_entry)
    db.flush()  # ensure ID/time assigned before commit
    db.commit()
    return {"found": found}

@app.post("/api/check-password")
async def check_password(input: CheckInput, email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    if not input.password:
        raise HTTPException(status_code=400, detail="Password is required")
    found = await check_hibp_password(input.password)
    result_text = "Breach found" if found else "Safe"
    # Do not store raw password
    history_entry = History(type="Password", input="***", result=result_text, time=datetime.utcnow())
    db.add(history_entry)
    db.flush()
    db.commit()
    return {"found": found}

@app.get("/api/history")
def get_history(email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    entries = db.query(History).order_by(History.time.desc()).limit(50).all()
    # Return ISO 8601 strings for time to ensure consistent rendering
    return [{
        "type": e.type,
        "input": e.input,
        "result": e.result,
        "time": (e.time.isoformat(timespec="seconds") if isinstance(e.time, datetime) else str(e.time)),
    } for e in entries]

@app.delete("/api/history")
def clear_history(email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(History).delete()
    db.flush()
    db.commit()
    return {"status": "cleared"}
