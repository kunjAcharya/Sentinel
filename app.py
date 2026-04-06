import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, redirect, url_for, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt
import os
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///local.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
if not os.path.exists("logs"):
    os.mkdir("logs")

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

handler = RotatingFileHandler("logs/security.log", maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
handler.setFormatter(formatter)
security_logger.addHandler(handler)

db = SQLAlchemy(app)

failed_attempts = defaultdict(list)
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = timedelta(minutes=10)
LOCKOUT_DURATION = timedelta(minutes=15)
locked_ips = {}

login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pw_hash = db.Column(db.LargeBinary(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def hash_pw(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_pw(pw: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(pw.encode(), pw_hash)

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            db.session.add(User(username="admin", pw_hash=hash_pw("Admin123!"), role="admin"))
            db.session.add(User(username="staff", pw_hash=hash_pw("Staff123!"), role="staff"))
            db.session.add(User(username="user", pw_hash=hash_pw("User123!"), role="user"))
            db.session.commit()

@app.route("/")
def home():
    if current_user.is_authenticated:
        return f"Logged in as {current_user.username} ({current_user.role}) | <a href='/logout'>Logout</a>"
    return "Not logged in | <a href='/login'>Login</a>"

@app.route("/login", methods=["GET", "POST"])
def login():
    login_html = """
    <h2>Login</h2>
    <form method="post">
      <input name="username" placeholder="username"/><br/>
      <input name="password" type="password" placeholder="password"/><br/>
      <button type="submit">Login</button>
    </form>
    <p style="color:red;">{{ msg }}</p>
    """
    if request.method == "POST":
        username = request.form["username"]
        u = User.query.filter_by(username=username).first()
        ip = request.remote_addr
        now = datetime.now()

        if ip in locked_ips:
            if now < locked_ips[ip]:
                security_logger.warning(
                    f"BLOCKED_LOGIN user={username} ip={ip} locked_until={locked_ips[ip]}"
                )
                return render_template_string(login_html, msg="Too many failed attempts. Try again later.")
            else:
                del locked_ips[ip]
                failed_attempts[ip] = []

        if not u or not check_pw(request.form["password"], u.pw_hash):
            failed_attempts[ip].append(now)
            failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < LOCKOUT_WINDOW]
            security_logger.warning(
                f"FAILED_LOGIN user={username} ip={ip} attempts={len(failed_attempts[ip])}"
            )
            if len(failed_attempts[ip]) >= LOCKOUT_THRESHOLD:
                locked_ips[ip] = now + LOCKOUT_DURATION
                security_logger.warning(f"IP_LOCKED ip={ip} until={locked_ips[ip]}")
                return render_template_string(login_html, msg="Too many failed attempts. Try again later.")
            return render_template_string(login_html, msg="Invalid credentials")

        login_user(u)
        security_logger.info(
            f"SUCCESS_LOGIN user={u.username} role={u.role} ip={request.remote_addr}"
        )
        return redirect(url_for("home"))

    return render_template_string(login_html, msg="")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        return "Forbidden", 403
    return "Welcome admin. This will become our secured admin panel."

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "admin":
        return "Forbidden", 403

    stats = {"total": 0, "failed": 0, "success": 0, "ip_fails": {}}

    try:
        with open("logs/security.log", "r") as f:
            for line in f:
                if "FAILED_LOGIN" in line:
                    stats["total"] += 1
                    stats["failed"] += 1
                    ip = line.split("ip=")[-1].split()[0].strip()
                    stats["ip_fails"][ip] = stats["ip_fails"].get(ip, 0) + 1
                elif "SUCCESS_LOGIN" in line:
                    stats["total"] += 1
                    stats["success"] += 1
    except FileNotFoundError:
        pass

    top_ips = sorted(stats["ip_fails"].items(), key=lambda x: x[1], reverse=True)[:5]

    dashboard_html = """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { background-color: #0a0a0a; color: #00ff41; font-family: 'Share Tech Mono', monospace; padding: 40px; }
      h2 { font-size: 1.8rem; letter-spacing: 4px; text-transform: uppercase; border-bottom: 1px solid #00ff41; padding-bottom: 12px; margin-bottom: 30px; }
      .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }
      .card { border: 1px solid #00ff4155; padding: 20px; background: #0f0f0f; }
      .card .label { font-size: 0.7rem; letter-spacing: 3px; color: #888; text-transform: uppercase; margin-bottom: 10px; }
      .card .value { font-size: 2.5rem; font-weight: bold; }
      .card.danger .value { color: #ff3333; }
      .card.success .value { color: #00ff41; }
      .card.neutral .value { color: #ffffff; }
      h3 { font-size: 0.8rem; letter-spacing: 3px; text-transform: uppercase; color: #888; margin-bottom: 15px; }
      table { width: 100%; border-collapse: collapse; }
      th { text-align: left; font-size: 0.7rem; letter-spacing: 2px; color: #555; text-transform: uppercase; padding: 8px 12px; border-bottom: 1px solid #1a1a1a; }
      td { padding: 10px 12px; border-bottom: 1px solid #111; font-size: 0.9rem; }
      tr:hover td { background: #111; }
      .badge { display: inline-block; padding: 2px 8px; font-size: 0.7rem; letter-spacing: 2px; background: #ff333322; color: #ff3333; border: 1px solid #ff333355; }
      .footer { margin-top: 40px; font-size: 0.7rem; color: #333; letter-spacing: 2px; }
    </style>

    <h2>⬡ Sentinel // Security Dashboard</h2>
    <div class="grid">
      <div class="card neutral"><div class="label">Total Attempts</div><div class="value">{{ stats.total }}</div></div>
      <div class="card success"><div class="label">Successful Logins</div><div class="value">{{ stats.success }}</div></div>
      <div class="card danger"><div class="label">Failed Logins</div><div class="value">{{ stats.failed }}</div></div>
    </div>
    <h3>Top IPs // Failed Attempts</h3>
        <table>
        <thead><tr><th>IP Address</th><th>Failed Attempts</th><th>Status</th></tr></thead>
        <tbody>
            {% for ip, count in top_ips %}
            <tr><td>{{ ip }}</td><td>{{ count }}</td><td><span class="badge">SUSPICIOUS</span></td></tr>
            {% endfor %}
        </tbody>
        </table>
        <div class="footer">SENTINEL v1.0 // ADMIN ACCESS ONLY // {{ stats.total }} EVENTS LOGGED</div>

        <h3 style="margin-top:40px;">Locked IPs // Active Blocks</h3>
    {% if locked_ips %}
    <table>
    <thead><tr><th>IP Address</th><th>Locked Until</th><th>Status</th></tr></thead>
    <tbody>
        {% for ip, until in locked_ips.items() %}
        <tr>
        <td>{{ ip }}</td>
        <td>{{ until.strftime('%Y-%m-%d %H:%M:%S') }}</td>
        <td><span style="display:inline-block;padding:2px 8px;font-size:0.7rem;letter-spacing:2px;background:#ff990022;color:#ff9900;border:1px solid #ff990055;">LOCKED</span></td>
        </tr>
        {% endfor %}
    </tbody>
    </table>
    {% else %}
    <p style="color:#555;font-size:0.8rem;letter-spacing:2px;">NO ACTIVE LOCKS</p>
    {% endif %}
    """
    return render_template_string(dashboard_html, stats=stats, top_ips=top_ips, locked_ips=locked_ips)
if __name__ == "__main__":
    init_db()
    app.run(debug=True)