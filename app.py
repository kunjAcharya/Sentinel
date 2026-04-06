import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, redirect, url_for, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///local.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
if not os.path.exists("logs"):
    os.mkdir("logs")

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    "logs/security.log",
    maxBytes=1_000_000,
    backupCount=5
)

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)
handler.setFormatter(formatter)
security_logger.addHandler(handler)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pw_hash = db.Column(db.LargeBinary(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # user | staff | admin

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
    html = """
    <h2>Login</h2>
    <form method="post">
      <input name="username" placeholder="username"/><br/>
      <input name="password" type="password" placeholder="password"/><br/>
      <button type="submit">Login</button>
    </form>
    <p style="color:red;">{{msg}}</p>
    """
    if request.method == "POST":
        username = request.form["username"]
        u = User.query.filter_by(username=username).first()

        if not u or not check_pw(request.form["password"], u.pw_hash):
            security_logger.warning(
                f"FAILED_LOGIN user={username} ip={request.remote_addr}"
            )
            return render_template_string(html, msg="Invalid credentials")

        login_user(u)
        security_logger.info(
            f"SUCCESS_LOGIN user={u.username} role={u.role} ip={request.remote_addr}"
        )
        return redirect(url_for("home"))

    return render_template_string(html, msg="")

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

if __name__ == "__main__":
    init_db()
    app.run(debug=True)