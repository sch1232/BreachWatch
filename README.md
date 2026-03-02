# BreachWatch

Check if an email or password appears in known data breaches. FastAPI backend + simple HTML/JS frontend.

Live
- Frontend: https://breachwatchapi.netlify.app/
- Backend API: https://breachwatch-api.onrender.com/api
- API Docs: https://breachwatch-api.onrender.com/docs

What it does
- Email check (Have I Been Pwned unifiedsearch, no API key)
- Password check (HIBP k‑anonymity)
- Recent checks saved to history (SQLite)

Tech
- FastAPI, Uvicorn, SQLAlchemy, SQLite, httpx, PyJWT, Passlib
- Vanilla HTML/CSS/JS
- Render (backend), Netlify (frontend)

Run locally (Windows)
1) Backend
- Open terminal in repo root:
  cd api\api
  python -m venv venv
  venv\Scripts\activate
  pip install -r requirements.txt
  set SECRET_KEY=dev-secret
  uvicorn app:app --reload
- Docs: http://127.0.0.1:8000/docs

2) Frontend
- Open web/index.html
- If using local API, set in index.html:
  const API = "http://127.0.0.1:8000/api";

Deploy (current setup)
- Backend (Render)
  - Build: pip install -r api/api/requirements.txt
  - Start: uvicorn api.api.app:app --host 0.0.0.0 --port $PORT
- Frontend (Netlify)
  - Base: web
  - Publish: web
  - API in index.html:
    const API = "https://breachwatch-api.onrender.com/api";

Notes
- Passwords are never stored (masked in history).
- If CORS errors in browser, allow your Netlify domain in FastAPI CORS.

Author
Sarthak