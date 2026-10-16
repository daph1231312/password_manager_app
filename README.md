# VaultKey: a small password manager (Flask)

A web-based password manager: register a user, log in with a master password, and store,
search, edit and delete password entries. Passwords are encrypted before they are written
to disk. Backend in Python (Flask), single-page frontend in plain HTML/JavaScript.

## Features

- User registration and login with a master password
- Add, view, edit, delete and search entries (title, password, URL, notes)
- Built-in random password generator
- Passwords stored encrypted: **AES-256-GCM** per entry
- Master passwords are never stored; only a salted **PBKDF2-HMAC-SHA256** hash (600,000 iterations)

## Run it

```bash
python -m venv venv
venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python task5.py
```

Open <http://localhost:5000> in a browser. The first time, register a user; the app creates
a `data/` folder next to the script for its files.

## Requirements

- Python 3.9+
- Packages: `flask`, `cryptography` (listed in `requirements.txt`)
- No accounts or API keys. Everything you need to provide is your own master password.

## API (used by the frontend)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/register`, `/api/login`, `/api/logout` | account and session |
| GET / POST | `/api/entries` | list / create entries |
| GET / PUT / DELETE | `/api/entries/<title>` | read / update / delete one entry |
| GET | `/api/generate-password` | random password |
| GET | `/api/search` | search entries |

## Important notes

- **Your data is never part of this repository.** The `data/` folder (users and encrypted
  entries) is listed in `.gitignore`. Do not commit it.
- Learning project: it has not been security-audited. The app runs with `debug=True` and generates
  a new session secret on every start, so sessions end when the server restarts. Do not use it
  to store passwords you cannot afford to lose.
