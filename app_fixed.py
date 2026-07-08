"""
====================================================================
  安全修复版 — 参数化查询 + bcrypt哈希 + 输入校验 (v2.0)
  端口: 5001
  修复: index从DB读取 / 注册密码哈希 / 登录查DB / 错误分层 / 校验
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
logging.basicConfig(level=logging.INFO, handlers=[_handler, logging.StreamHandler()])
logger = logging.getLogger("auth")

DB_PATH = "data/users.db"
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        role TEXT DEFAULT 'user',
        balance INTEGER DEFAULT 0
    )""")
    # 预置用户密码用 bcrypt 哈希
    c.execute("INSERT OR REPLACE INTO users VALUES (1,'admin',?,'admin@example.com','13800138000','admin',99999)",(bcrypt.hash("admin123"),))
    c.execute("INSERT OR REPLACE INTO users VALUES (2,'alice',?,'alice@example.com','13900139001','user',100)",(bcrypt.hash("alice2025"),))
    c.execute("INSERT OR REPLACE INTO users VALUES (3,'bob',?,'bob@example.com','13700137000','user',50)",(bcrypt.hash("bob2025"),))
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

LOGIN_AT = {}; LOCK_MIN, MAX_AT = 5, 5
def _lk(u): return f"{request.remote_addr}:{u}"
def _is_lk(u): n=time();k=_lk(u);a=[t for t in LOGIN_AT.get(k,[]) if n-t<LOCK_MIN*60];LOGIN_AT[k]=a;return len(a)>=MAX_AT
def _rf(u): LOGIN_AT.setdefault(_lk(u),[]).append(time())
def _cl(u): LOGIN_AT.pop(_lk(u),None)

# ─────────────────────────────
#  首页: 参数化查询从DB读用户信息
# ─────────────────────────────
@app.route("/")
def index():
    uname = session.get("username"); user_info = None
    if uname:
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor()
            c.execute("SELECT username, email, phone, role, balance FROM users WHERE username=?", (uname,))
            row = c.fetchone(); conn.close()
            if row: user_info = {"username":row[0],"email":row[1],"phone":row[2],"role":row[3],"balance":row[4]}
        except Exception as e:
            logger.error("首页查询异常: %s", e)
    return render_template("index_safe.html", username=uname, user=user_info)

# ─────────────────────────────
#  登录: 查DB bcrypt验证 + 暴力破解防护
# ─────────────────────────────
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not _csrf_v(): return render_template("login.html",error="无效请求"),400
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if _is_lk(u): return render_template("login.html",error=f"请{LOCK_MIN}分钟后再试")
        valid = False
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?", (u,))
            row = c.fetchone(); conn.close()
            if row and verify_pw(p, row[0]): valid = True
        except Exception as e:
            logger.error("登录查询异常: %s", e)
        if valid:
            session.permanent=True; session["username"]=u; _cl(u); logger.info("登录成功: %s", u)
            return redirect(url_for("index"))
        else:
            _rf(u); logger.warning("登录失败: %s", u)
            return render_template("login.html",error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("登出: %s", session.get("username")); session.clear(); return redirect(url_for("index"))

# ────────────────────────────────────────────────
#  搜索: 参数化查询 + 显示绑定参数
# ────────────────────────────────────────────────
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []; sql_safe = ""; params = (); row_count = 0; param_display = ""
    if keyword:
        sql_safe = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_val = f"%{keyword}%"; params = (like_val, like_val)
        param_display = f"参数1: {like_val!r}, 参数2: {like_val!r}"
        print("\n[安全SQL]", sql_safe, "参数:", params)
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor(); c.execute(sql_safe, params); results = c.fetchall(); conn.close()
            row_count = len(results)
        except Exception as e:
            logger.error("搜索异常: %s", e)
            return render_template("index_safe.html", username=session.get("username"),
                user=_get_user(session.get("username")), error_msg="查询异常，请稍后再试")
    return render_template("index_safe.html", username=session.get("username"),
        user=_get_user(session.get("username")), search_results=results,
        keyword=keyword, sql_safe=sql_safe, param_display=param_display, row_count=row_count)

def _get_user(uname):
    if not uname: return None
    try:
        conn = sqlite3.connect(DB_PATH); c = conn.cursor()
        c.execute("SELECT username,email,phone,role,balance FROM users WHERE username=?", (uname,))
        row = c.fetchone(); conn.close()
        if row: return {"username":row[0],"email":row[1],"phone":row[2],"role":row[3],"balance":row[4]}
    except: pass
    return None

# ────────────────────────────────────────────────
#  注册: bcrypt哈希 + 参数化查询 + 输入校验
# ────────────────────────────────────────────────
@app.route("/register", methods=["GET","POST"])
def register():
    errors = {}; old = {}
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        e = request.form.get("email","").strip()
        ph = request.form.get("phone","").strip()
        old = {"username":u,"password":p,"email":e,"phone":ph}

        # ── 输入校验 ──
        if len(u) < 2: errors["username"] = "用户名至少2个字符"
        elif len(u) > 20: errors["username"] = "用户名不超过20个字符"
        elif not re.match(r'^[a-zA-Z0-9_一-龥]+$', u): errors["username"] = "用户名只能包含字母、数字、下划线、中文"
        if len(p) < 6: errors["password"] = "密码至少6位"
        if e and '@' not in e: errors["email"] = "邮箱格式不正确（需包含@）"
        if ph and not re.match(r'^\d{7,15}$', ph): errors["phone"] = "手机号应为7-15位数字"

        if not errors:
            try:
                pw_hash = hash_pw(p)
                conn = sqlite3.connect(DB_PATH); c = conn.cursor()
                c.execute("INSERT INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, 'user', 0)",
                         (u, pw_hash, e, ph))
                conn.commit(); conn.close()
                logger.info("新用户注册: %s", u)
                return render_template("login.html", error="注册成功，请登录")
            except sqlite3.IntegrityError:
                errors["username"] = "用户名已存在"
            except Exception as ex:
                logger.error("注册异常: %s", ex)
                return render_template("register_safe.html", error="系统异常，请稍后再试", old=old)
    return render_template("register_safe.html", errors=errors, old=old)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5001)
