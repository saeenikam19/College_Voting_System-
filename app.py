from flask import Flask, render_template, request, redirect, session, url_for, flash, Response, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import csv
import io

# Security and realtime extensions
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer

# --------------------------------------------------
# APP SETUP
# --------------------------------------------------
app = Flask(__name__)
app.secret_key = "secret123"

# --------------------------------------------------
# DATABASE
# --------------------------------------------------
DATABASE = "database.db"

def init_db():
    db = sqlite3.connect(DATABASE)
    cur = db.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        voted INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_id INTEGER,
        candidate_id INTEGER,
        timestamp TEXT,
        FOREIGN KEY(voter_id) REFERENCES users(id),
        FOREIGN KEY(candidate_id) REFERENCES candidates(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        rating INTEGER,
        comments TEXT,
        timestamp TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        user TEXT,
        details TEXT,
        timestamp TEXT
    )
    """)

    db.commit()
    db.close()

# 🔥 Initialize database ON STARTUP
init_db()

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# --------------------------------------------------
# EXTENSIONS
# --------------------------------------------------
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
socketio = SocketIO(app, async_mode="threading")
serializer = URLSafeTimedSerializer(app.secret_key)

# --------------------------------------------------
# DB CONNECTION
# --------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db:
        db.close()

# --------------------------------------------------
# CSRF
# --------------------------------------------------
@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Invalid CSRF token", "danger")
    return redirect(url_for("login"))

# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def get_user_by_username(username):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row

def get_results():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT c.id, c.name, COUNT(v.id) AS count
        FROM candidates c
        LEFT JOIN votes v ON v.candidate_id = c.id
        GROUP BY c.id
        ORDER BY count DESC
    """)
    rows = cur.fetchall()
    total = sum(r["count"] for r in rows)
    return [{
        "id": r["id"],
        "name": r["name"],
        "count": r["count"],
        "percent": round((r["count"] / total * 100), 2) if total else 0
    } for r in rows]

# --------------------------------------------------
# ROUTES
# --------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        u = get_user_by_username(user)

        if u and check_password_hash(u["password"], pwd):
            session["user_id"] = u["id"]
            session["username"] = u["username"]
            session["role"] = u["role"]
            return redirect(url_for("admin" if u["role"] == "admin" else "vote"))

        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users(username, password, role) VALUES (?,?,?)",
                (user, generate_password_hash(pwd), "voter")
            )
            db.commit()
            flash("Registration successful", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username exists", "danger")
    return render_template("register.html")

@app.route("/vote", methods=["GET", "POST"])
def vote():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        cid = request.form.get("candidate")
        cur.execute(
            "INSERT INTO votes(voter_id, candidate_id, timestamp) VALUES (?,?,?)",
            (session["user_id"], cid, datetime.utcnow().isoformat())
        )
        cur.execute("UPDATE users SET voted=1 WHERE id=?", (session["user_id"],))
        db.commit()
        flash("Vote recorded", "success")

    candidates = cur.execute("SELECT * FROM candidates").fetchall()
    return render_template("vote.html", candidates=candidates)

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin.html", results=get_results())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8000)
