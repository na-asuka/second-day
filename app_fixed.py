"""
====================================================================
  安全修复版 — 全部使用参数化查询(?) 防止SQL注入
  功能: 登录 / 注册 / 搜索（全部使用 ? 占位符）
  端口: 5001
====================================================================
"""
import os, re, secrets, sqlite3, logging
from time import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, session, url_for
from passlib.hash import bcrypt
from werkzeug.middleware.proxy_fix import ProxyFix

_handler = RotatingFileHandler("login_audit.log", maxBytes=5*1024*1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[_handler, logging.StreamHandler()])
logger = logging.getLogger("auth")

DB_PATH = "data/users.db"
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, email TEXT, phone TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@example.com','13800138000')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','alice2025','alice@example.com','13900139001')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3,'bob','bob2025','bob@example.com','13700137000')")
    c.execute("INSERT OR IGNORE INTO users VALUES (4,'eve','eve2025','eve@example.com','13600136000')")
    conn.commit(); conn.close()
init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key: raise RuntimeError("SECRET_KEY 未设置")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=True if os.environ.get("FORCE_HTTPS") else False)
app.permanent_session_lifetime = timedelta(hours=2)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _https():
        if not request.is_secure: return redirect(request.url.replace("http://","https://",1),301)
@app.after_request
def _headers(r):
    r.headers.update({"X-Frame-Options":"DENY","X-Content-Type-Options":"nosniff","Content-Security-Policy":"default-src 'self'"})
    return r
@app.context_processor
def _csrf():
    session.setdefault("_csrf_token", secrets.token_hex(32))
    return {"csrf_token": session["_csrf_token"]}
def _csrf_v():
    t = request.form.get("_csrf_token")
    return bool(t and secrets.compare_digest(t, session.get("_csrf_token","")))
def hash_pw(p): return bcrypt.hash(p)
def verify_pw(p, h):
    try: return bcrypt.verify(p, h)
    except: return False

admin_pw = os.environ.get("ADMIN_INIT_PASS") or "admin123"
alice_pw = os.environ.get("ALICE_INIT_PASS") or "alice2025"
USERS = {
    "admin": {"username":"admin","password":hash_pw(admin_pw),"role":"admin","email":"admin@example.com","phone":"13800138000","balance":99999},
    "alice": {"username":"alice","password":hash_pw(alice_pw),"role":"user","email":"alice@example.com","phone":"13900139001","balance":100},
}
LOGIN_AT = {}; LOCK_MIN, MAX_AT = 5, 5
def _lk(u): return f"{request.remote_addr}:{u}"
def _is_lk(u): n=time();k=_lk(u);a=[t for t in LOGIN_AT.get(k,[]) if n-t<LOCK_MIN*60];LOGIN_AT[k]=a;return len(a)>=MAX_AT
def _rf(u): LOGIN_AT.setdefault(_lk(u),[]).append(time())
def _cl(u): LOGIN_AT.pop(_lk(u),None)

@app.route("/")
def index():
    u = session.get("username"); ui = None
    if u in USERS: ui = USERS[u].copy(); ui.pop("password")
    return render_template("index_safe.html", username=u, user=ui)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not _csrf_v(): return render_template("login.html",error="无效请求"),400
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if _is_lk(u): return render_template("login.html",error=f"请{LOCK_MIN}分钟后再试")
        try: user = USERS.get(u); v = user and verify_pw(p, user["password"])
        except Exception: v = False
        if v:
            session.permanent=True; session["username"]=u; _cl(u)
            logger.info("登录成功: %s", u); return redirect(url_for("index"))
        else: _rf(u); logger.warning("登录失败: %s", u); return render_template("login.html",error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("登出: %s", session.get("username")); session.clear(); return redirect(url_for("index"))

# ═══════════════════════════════════════════════════════════════
#  [安全版] 搜索 — 参数化查询 ? 占位符
# ═══════════════════════════════════════════════════════════════
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []
    sql_safe = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    params = ()

    if keyword:
        params = (f"%{keyword}%", f"%{keyword}%")
        print("\n[安全SQL]", sql_safe, "参数:", params)
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(sql_safe, params)
            results = c.fetchall()
            conn.close()
        except Exception as e:
            print("[SQL错误]", e)

    u = session.get("username"); ui = None
    if u in USERS: ui = USERS[u].copy(); ui.pop("password")
    return render_template("index_safe.html", username=u, user=ui, search_results=results, keyword=keyword)

# ═══════════════════════════════════════════════════════════════
#  [安全版] 注册 — 参数化查询 ? 占位符
# ═══════════════════════════════════════════════════════════════
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        e = request.form.get("email","").strip()
        ph = request.form.get("phone","").strip()
        sql_safe = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print("\n[安全SQL]", sql_safe, "参数:", (u,p,e,ph))
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(sql_safe, (u,p,e,ph))
            conn.commit(); conn.close()
            return render_template("login.html", error="注册成功，请登录")
        except Exception as ex:
            print("[SQL错误]", ex)
            return render_template("register_safe.html", error="注册失败，用户名可能已存在")
    return render_template("register_safe.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5001)
