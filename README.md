# 🔍 GitHub Secret Scanner

A full-stack app to detect hardcoded secrets in GitHub repositories.

## Project Structure

```
github-secret-scanner/
├── backend/
│   └── main.py          ← FastAPI backend
└── frontend/
    └── index.html       ← Dashboard UI (open in browser)
```

## Quick Start

### 1. Install Backend Dependencies

```bash
pip install fastapi uvicorn httpx python-multipart aiohttp
```

### 2. Run the Backend

```bash
cd backend
uvicorn main:app --reload --port 8000
```

API docs available at: http://localhost:8000/docs

### 3. Open the Frontend

Open `frontend/index.html` directly in your browser.

> No build tools required — it's a single HTML file.

---

## Features

- **13 secret patterns** — AWS keys, GitHub tokens, Stripe keys, JWTs, DB URLs, passwords, emails, and more
- **Severity levels** — Critical / High / Medium / Low / Info
- **Full repo crawl** — Uses GitHub Git Trees API for complete file traversal
- **Live progress** — Real-time scanning progress bar
- **Findings dashboard** — Filter by severity, view file + line number
- **Download results** — Export findings as JSON
- **Scan history** — Persisted in localStorage
- **GitHub Token support** — Scan private repos or bypass rate limits

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scan/{id}` | Poll scan status + results |
| GET | `/api/scan/{id}/download` | Download findings as JSON |
| GET | `/api/scans` | List all scans |
| DELETE | `/api/scan/{id}` | Delete a scan |

---

## Detected Secret Types

| Secret | Severity |
|--------|----------|
| AWS Access/Secret Key | 🔴 Critical |
| Stripe Secret Key | 🔴 Critical |
| Private Key (RSA/EC) | 🔴 Critical |
| GitHub Token | 🟠 High |
| Google API Key | 🟠 High |
| Slack Token | 🟠 High |
| JWT Token | 🟠 High |
| Database URL | 🟡 Medium |
| Generic API Key | 🟡 Medium |
| Bearer Token | 🟡 Medium |
| Hardcoded Password | 🟢 Low |
| Hardcoded Email | ℹ Info |
