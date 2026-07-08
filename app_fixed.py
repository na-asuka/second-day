"""
============================================================
  安全版 app.py — 已修复 SQL 注入漏洞
  对比漏洞版 app.py（使用 f-string 拼接）
  修复方式：参数化查询 (?) 代替字符串拼接
============================================================
"""

import os
import re
import secrets
import sqlite3
import logging
from time import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, session, url_for
from passlib.hash import bcrypt
from werkzeug.middleware.proxy_fix import ProxyFix

# ── 日志配置 ──
_handler = RotatingFileHandler("login_audit.log", maxBytes=5 * 1024 * 1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[_handler, logging.StreamHandler()])
logger = logging.getLogger("auth")

# ── 数据库初始化 ──
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "users.db")

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[数据库] 初始化完成")

init_db()

# ── Flask 应用 ──
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("环境变量 SECRET_KEY 未设置")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True if os.environ.get("FORCE_HTTPS") else False,
)
app.permanent_session_lifetime = timedelta(hours=2)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _redirect_to_https():
        if not request.is_secure:
            return redirect(request.url.replace("http://", "https://", 1), 301)

@app.after_request
def _set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@app.context_processor
def _inject_csrf_token():
    session.setdefault("_csrf_token", secrets.token_hex(32))
    return {"csrf_token": session["_csrf_token"]}

def _csrf_validate():
    token = request.form.get("_csrf_token")
    return bool(token and secrets.compare_digest(token, session.get("_csrf_token", "")))

# ── bcrypt ──
def hash_password(plain): return bcrypt.hash(plain)

def verify_password(plain, hashed):
    try: return bcrypt.verify(plain, hashed)
    except: return False

admin_pass = os.environ.get("ADMIN_INIT_PASS")
if not admin_pass: raise RuntimeError("ADMIN_INIT_PASS 未设置")
alice_pass = os.environ.get("ALICE_INIT_PASS")
if not alice_pass: raise RuntimeError("ALICE_INIT_PASS 未设置")

USERS = {
    "admin": {"username": "admin", "password": hash_password(admin_pass), "role": "admin",
              "email": "admin@example.com", "phone": "13800138000", "balance": 99999},
    "alice": {"username": "alice", "password": hash_password(alice_pass), "role": "user",
              "email": "alice@example.com", "phone": "13900139001", "balance": 100},
}
del admin_pass, alice_pass

LOGIN_ATTEMPTS = {}
LOCK_MINUTES, MAX_ATTEMPTS = 5, 5

def _lock_key(username):
    return f"{request.remote_addr}:{username}"

def _is_locked(username):
    now = time(); key = _lock_key(username)
    attempts = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOCK_MINUTES * 60]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def _record_failure(username):
    LOGIN_ATTEMPTS.setdefault(_lock_key(username), []).append(time())

def _clear_attempts(username):
    LOGIN_ATTEMPTS.pop(_lock_key(username), None)

# ── 路由 ──
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username in USERS:
        user_info = USERS[username].copy()
        user_info.pop("password")
    return render_template("index.html", username=username, user=user_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _csrf_validate():
            return render_template("login.html", error="无效请求"), 400
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _is_locked(username):
            return render_template("login.html", error=f"请{LOCK_MINUTES}分钟后再试")
        try:
            user = USERS.get(username)
            valid = user and verify_password(password, user["password"])
        except Exception:
            valid = False
        if valid:
            session.permanent = True; session["username"] = username
            _clear_attempts(username)
            logger.info("登录成功: %s", username)
            return redirect(url_for("index"))
        else:
            _record_failure(username)
            logger.warning("登录失败: %s", username)
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("用户登出: %s", session.get("username"))
    session.clear()
    return redirect(url_for("index"))

# ═══════════════════════════════════════════════════════════════
#  [修复版] 注册功能 — 使用参数化查询 (?) 防止 SQL 注入
# ═══════════════════════════════════════════════════════════════
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not _csrf_validate():
            return render_template("register.html", error="无效请求"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # ── 修复：使用 ? 占位符的参数化查询 ──
        #     漏洞版使用: f"INSERT INTO users VALUES ('{username}', ...)"
        #     攻击者输入:  hacker', 'pass', 'h@x.com', '123')--
        #     生成 SQL:   INSERT INTO users VALUES ('hacker', 'pass', 'h@x.com', '123')--', ...)
        #     导致任意数据插入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print("[SQL-安全]", sql, "参数:", (username, password, email, phone))

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(sql, (username, password, email, phone))  # ← 参数化查询
            conn.commit()
            conn.close()
            return render_template("login.html", error="注册成功，请登录")
        except Exception as e:
            print("[SQL错误]", e)
            return render_template("register.html", error="注册失败，用户名可能已存在")

    return render_template("register.html")


# ═══════════════════════════════════════════════════════════════
#  [修复版] 搜索功能 — 使用参数化查询 (?) 防止 SQL 注入
# ═══════════════════════════════════════════════════════════════
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []
    if keyword:
        # ── 修复：使用 ? 占位符的参数化查询 ──
        #     漏洞版使用: f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"
        #     攻击者输入:  ' OR '1'='1
        #     生成 SQL:   SELECT * FROM users WHERE username LIKE '%' OR '1'='1%'
        #     返回全部用户数据
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"  # keyword 本身作为数据传入，不会被解析为 SQL 代码
        print("[SQL-安全]", sql, "参数:", (like_param, like_param))

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(sql, (like_param, like_param))  # ← 参数化查询
            results = c.fetchall()
            conn.close()
        except Exception as e:
            print("[SQL错误]", e)

    username = session.get("username")
    user_info = None
    if username in USERS:
        user_info = USERS[username].copy()
        user_info.pop("password")
    return render_template("index.html", username=username, user=user_info, search_results=results, keyword=keyword)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5001)  # 使用 5001 端口，与漏洞版区分
