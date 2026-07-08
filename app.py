"""
====================================================================
  安全版 — 参数化查询 (?) 防止 SQL 注入
  端口: 5000
  修复方式: 全部 SQL 使用 ? 占位符
  功能: 登录 / 注册 / 搜索 / 信息展示
====================================================================
"""
import os, sqlite3, logging
from time import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, session, url_for
from passlib.hash import bcrypt
from werkzeug.middleware.proxy_fix import ProxyFix

_handler = RotatingFileHandler("login_audit.log", maxBytes=5*1024*1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler, logging.StreamHandler()])
logger = logging.getLogger("auth")

DB_PATH = "data/users.db"
def init_db():
    os.makedirs("data", exist_ok=True); conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, email TEXT, phone TEXT, role TEXT DEFAULT 'user', balance INTEGER DEFAULT 0)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin',?,'admin@example.com','13800138000','admin',99999)",(bcrypt.hash("admin123"),))
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice',?,'alice@example.com','13900139001','user',100)",(bcrypt.hash("alice2025"),))
    c.execute("INSERT OR IGNORE INTO users VALUES (3,'bob',?,'bob@example.com','13700137000','user',50)",(bcrypt.hash("bob2025"),))
    conn.commit(); conn.close()
init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key: raise RuntimeError("SECRET_KEY 未设置")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=True if os.environ.get("FORCE_HTTPS") else False)
app.permanent_session_lifetime = timedelta(hours=2)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _https():
        if not request.is_secure: return redirect(request.url.replace("http://","https://",1),301)
@app.after_request
def _headers(r):
    r.headers.update({"X-Frame-Options":"DENY","X-Content-Type-Options":"nosniff"})
    return r
@app.context_processor
def _csrf():
    session.setdefault("_csrf_token", os.urandom(16).hex())
    return {"csrf_token": session["_csrf_token"]}
def _csrf_v():
    t = request.form.get("_csrf_token")
    return bool(t and t == session.get("_csrf_token",""))

def hash_pw(p): return bcrypt.hash(p)
def verify_pw(p, h):
    try: return bcrypt.verify(p, h)
    except: return False

LOGIN_AT = {}; LOCK_MIN, MAX_AT = 5, 5
def _lk(u): return f"{request.remote_addr}:{u}"
def _is_lk(u): n=time();k=_lk(u);a=[t for t in LOGIN_AT.get(k,[]) if n-t<LOCK_MIN*60];LOGIN_AT[k]=a;return len(a)>=MAX_AT
def _rf(u): LOGIN_AT.setdefault(_lk(u),[]).append(time())
def _cl(u): LOGIN_AT.pop(_lk(u),None)

@app.route("/")
def index():
    uname = session.get("username"); ui = None
    if uname:
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor()
            c.execute("SELECT username,email,phone,role,balance FROM users WHERE username=?", (uname,))
            r=c.fetchone();conn.close()
            if r: ui={"username":r[0],"email":r[1],"phone":r[2],"role":r[3],"balance":r[4]}
        except Exception as e: logger.error("首页异常: %s",e)
    return render_template("index.html", username=uname, user=ui)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not _csrf_v(): return render_template("login.html",error="无效请求"),400
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        if _is_lk(u): return render_template("login.html",error=f"请{LOCK_MIN}分钟后再试")
        valid=False
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?", (u,))
            r=c.fetchone();conn.close()
            if r and verify_pw(p, r[0]): valid=True
        except Exception as e: logger.error("登录异常: %s",e)
        if valid:
            session.permanent=True;session["username"]=u;_cl(u);logger.info("登录: %s",u)
            return redirect(url_for("index"))
        else: _rf(u);logger.warning("登录失败: %s",u);return render_template("login.html",error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("登出: %s",session.get("username"));session.clear();return redirect(url_for("index"))

@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword","").strip(); results=[]
    if keyword:
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_val = f"%{keyword}%"
        print("\n[安全SQL]", sql, "参数:", (like_val, like_val))
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor();c.execute(sql, (like_val, like_val));results=c.fetchall();conn.close()
        except Exception as e: logger.error("搜索异常: %s",e)
    uname=session.get("username");ui=None
    if uname:
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor()
            c.execute("SELECT username,email,phone,role,balance FROM users WHERE username=?", (uname,))
            r=c.fetchone();conn.close()
            if r: ui={"username":r[0],"email":r[1],"phone":r[2],"role":r[3],"balance":r[4]}
        except: pass
    return render_template("index.html", username=uname, user=ui, search_results=results, keyword=keyword)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        e=request.form.get("email","").strip(); ph=request.form.get("phone","").strip()
        pw_hash = hash_pw(p)
        sql = "INSERT INTO users (username,password,email,phone,role,balance) VALUES (?,?,?,?,'user',0)"
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor();c.execute(sql, (u, pw_hash, e, ph));conn.commit();conn.close()
            return render_template("login.html",error="注册成功，请登录")
        except: return render_template("register.html",error="注册失败")
    return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
