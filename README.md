# Sentinel

A lightweight Flask web application demonstrating secure authentication and role-based access control (RBAC) — built with real-world security principles, not just functionality.

---

## What It Does

Sentinel is a backend authentication system with three distinct user roles: **user**, **staff**, and **admin**. Each role has access to different parts of the application, enforced server-side on every request. It's designed to simulate how access control works in real enterprise environments — where who you are determines what you can see.

---

## Security Design Decisions

### Password Hashing with bcrypt
Passwords are never stored in plain text. Every password is hashed and salted using bcrypt before it touches the database. Even if the database were fully compromised, an attacker would have no usable credentials.

**Why bcrypt specifically?** It's deliberately slow — computationally expensive by design — which makes brute-force and rainbow table attacks impractical compared to faster algorithms like MD5 or SHA-1.

### Role-Based Access Control (RBAC)
Three tiers: `user`, `staff`, and `admin`. Access to protected routes is checked server-side on every request — not just at login. Guessing an admin URL while logged in as a regular user returns a `403 Forbidden`, not the page.

### Structured Security Audit Logging
Every login attempt — successful or failed — is logged with:
- Timestamp
- Username attempted
- Outcome (SUCCESS / FAILED)
- Source IP address

Logs rotate automatically at 1MB, keeping the last 5 files. This creates a forensic trail for detecting brute-force attempts, credential stuffing, or unauthorized access patterns — a requirement in most compliance frameworks (SOC 2, ISO 27001, ASD ISM).

### Environment Variable Secrets Management
The `SECRET_KEY` and `DATABASE_URL` are loaded from environment variables, not hardcoded in source code. This means the codebase can be public (e.g. on GitHub) without exposing credentials — a basic but critical separation of code and config.

---

## Tech Stack

- **Python / Flask** — web framework
- **Flask-Login** — session and authentication management
- **Flask-SQLAlchemy** — ORM, SQLite by default
- **bcrypt** — password hashing
- **Python logging (RotatingFileHandler)** — audit trail

---

## Running Locally

```bash
# Install dependencies
pip install flask flask_sqlalchemy flask_login bcrypt

# Set environment variables (optional, defaults to dev values)
export SECRET_KEY=your-secret-key
export DATABASE_URL=sqlite:///local.db

# Run
python app.py
```

Default accounts seeded on first run:

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | Admin123!  | admin |
| staff    | Staff123!  | staff |
| user     | User123!   | user  |

> **Note:** Change these credentials before any real deployment.

---

## Known Limitations / What I'd Add Next

- **No rate limiting on login** — currently vulnerable to brute-force. Next step: implement `Flask-Limiter` to cap attempts per IP.
- **Inline HTML templates** — moved to proper Jinja2 template files for production.
- **No staff-specific route yet** — role exists in the model, dedicated endpoint is next.
- **SQLite** — fine for local dev, would swap to PostgreSQL for production.

These aren't oversights — they're the next iteration. Security systems are never "done."

---

## Why I Built It This Way

Most beginner auth tutorials store passwords in plain text and check roles with a simple if/else. Sentinel is built the way a security engineer would think about it — layered controls, audit visibility, and secrets management from the start. The goal wasn't just to make it work, but to make it defensible.

---

*Built as part of a cybersecurity portfolio — Kunj Patel, Bachelor of IT (Cybersecurity), CQU Melbourne*
