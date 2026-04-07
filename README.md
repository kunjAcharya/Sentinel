
# Sentinel

A Flask-based authentication system built with real security principles, not just functionality. Sentinel demonstrates how access control, threat detection, and security monitoring work together in a production-minded application.

---

## Features

- Three-tier role-based access control (user / staff / admin)
- Bcrypt password hashing with salt
- Brute force protection with automatic IP lockout after 5 failed attempts
- Structured audit logging with rotating log files
- Live admin security dashboard with real-time event feed
- Color coded alerts for failed logins, blocked attempts, and successful logins
- Active IP lockout panel with expiry timestamps
- Dashboard auto-refreshes every 10 seconds
- Environment variable secrets management
- Dark terminal UI for login and dashboard

---

## Security Design Decisions

### Password Hashing with bcrypt
Passwords are never stored in plain text. Every password is hashed and salted using bcrypt before it touches the database. Even if the database were fully compromised, an attacker would have no usable credentials.

Why bcrypt specifically? It is deliberately slow by design, making brute force and rainbow table attacks impractical compared to faster algorithms like MD5 or SHA-1.

### Role-Based Access Control (RBAC)
Three tiers: user, staff, and admin. Access to protected routes is checked server-side on every request, not just at login. Guessing an admin URL while logged in as a regular user returns a 403 Forbidden, not the page.

### Brute Force Protection and IP Lockout
After 5 failed login attempts within a 10 minute window, the offending IP is automatically locked out for 15 minutes. Every block is logged and visible on the admin dashboard with exact expiry times.

### Structured Security Audit Logging
Every login attempt, successful or failed, is logged with timestamp, username, outcome, and source IP. Logs rotate automatically at 1MB keeping the last 5 files. This creates a forensic trail for detecting brute force attempts, credential stuffing, or unauthorized access patterns — a requirement in most compliance frameworks like SOC 2, ISO 27001, and ASD ISM.

### Live Security Dashboard
Admins can monitor login activity in real time. The dashboard shows total attempts, success and failure counts, top suspicious IPs, actively locked IPs with expiry times, and a live color coded event feed that updates every 10 seconds.

### Environment Variable Secrets Management
The SECRET_KEY and DATABASE_URL are loaded from environment variables, not hardcoded in source code. The codebase can be public without exposing credentials.

---

## Tech Stack

- Python / Flask
- Flask-Login
- Flask-SQLAlchemy
- bcrypt
- Python logging with RotatingFileHandler
- SQLite (dev) / PostgreSQL ready

---

## Running Locally

```bash
pip install flask flask_sqlalchemy flask_login bcrypt

export SECRET_KEY=your-secret-key
export DATABASE_URL=sqlite:///local.db

python app.py
```

Default accounts seeded on first run:

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | Admin123!  |admin  |
| staff    | Staff123!  | staff |
| user     | User123!   | user  |

Change these credentials before any real deployment.

---

## Known Limitations and Next Steps

- No rate limiting per user, only per IP. Next step: Flask-Limiter for per-account lockout.
- Inline HTML templates. Production version would use proper Jinja2 template files.
- No staff-specific route yet. Role exists in the model, dedicated endpoint is next.
- SQLite for local dev. PostgreSQL for production.
- Lockout state lives in memory and resets on app restart. Next step: persist lockout state to the database.

---

## Changelog

**v2.0**
- Brute force detection and automatic IP lockout
- Live security dashboard with real-time event feed
- Color coded alerts for failed, blocked, and successful logins
- Dark terminal UI for login page and dashboard

**v1.0**
- Initial release with RBAC, bcrypt hashing, and audit logging

---

*Built as part of a cybersecurity portfolio — Kunj Acharya, Bachelor of IT (Cybersecurity), CQU Melbourne*
