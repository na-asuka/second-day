"""
====================================================================
  漏洞演示版 — SQL注入纵深测试平台 (v2.0)
  端口: 5000
  注入类型: UNION / OR / AND布尔盲注 / 报错 / LIKE通配符 / 堆叠 / INSERT
  核心缺陷: index从DB读数据，注册数据可正常展示
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
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        role TEXT DEFAULT 'user',
        balance INTEGER DEFAULT 0
    )""")
    # 默认用户
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@example.com','13800138000','admin',99999)")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','alice2025','alice@example.com','13900139001','user',100)")
    c.execute("INSERT OR IGNORE INTO users VALUES (3,'bob','bob2025','bob@example.com','13700137000','user',50)")
    c.execute("INSERT OR IGNORE INTO users VALUES (4,'eve','eve2025','eve@example.com','13600136000','user',30)")
    conn.commit(); conn.close()
    print("[数据] 初始化完成")
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

# ═══ bcrypt ═══
def hash_pw(p): return bcrypt.hash(p)
def verify_pw(p, h):
    try: return bcrypt.verify(p, h)
    except: return False

# USERS 仅保留预置管理员（登录用）
USERS = {
    "admin": {"password": hash_pw(os.environ.get("ADMIN_INIT_PASS","admin123")),
              "role":"admin","email":"admin@example.com","phone":"13800138000","balance":99999},
    "alice": {"password": hash_pw(os.environ.get("ALICE_INIT_PASS","alice2025")),
              "role":"user","email":"alice@example.com","phone":"13900139001","balance":100},
}

LOGIN_AT = {}; LOCK_MIN, MAX_AT = 5, 5
def _lk(u): return f"{request.remote_addr}:{u}"
def _is_lk(u):
    n=time();k=_lk(u);a=[t for t in LOGIN_AT.get(k,[]) if n-t<LOCK_MIN*60];LOGIN_AT[k]=a;return len(a)>=MAX_AT
def _rf(u): LOGIN_AT.setdefault(_lk(u),[]).append(time())
def _cl(u): LOGIN_AT.pop(_lk(u),None)

# ─────────────────────────────
#  首页: 从数据库读取用户信息（f-string）
# ─────────────────────────────
@app.route("/")
def index():
    uname = session.get("username")
    user_info = None
    if uname:
        sql = f"SELECT username, email, phone, role, balance FROM users WHERE username='{uname}'"
        print("[漏洞SQL-index]", sql)
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor(); c.execute(sql); row = c.fetchone(); conn.close()
            if row:
                user_info = {"username":row[0],"email":row[1],"phone":row[2],"role":row[3],"balance":row[4]}
        except Exception as e:
            print("[SQL错误]", e)
    return render_template("index.html", username=uname, user=user_info)

# ─────────────────────────────
#  登录: 同时查DB和USERS字典
# ─────────────────────────────
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not _csrf_v(): return render_template("login.html",error="无效请求"),400
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if _is_lk(u): return render_template("login.html",error=f"请{LOCK_MIN}分钟后再试")
        valid = False
        # 先查字典（预置管理员bcrypt）
        if u in USERS and verify_pw(p, USERS[u]["password"]):
            valid = True
        # 再查数据库（注册用户的明文密码）
        if not valid:
            sql = f"SELECT password FROM users WHERE username='{u}'"
            try:
                conn = sqlite3.connect(DB_PATH); c = conn.cursor(); c.execute(sql); row = c.fetchone(); conn.close()
                if row and row[0] == p:
                    valid = True
            except: pass
        if valid:
            session.permanent=True; session["username"]=u; _cl(u)
            logger.info("登录成功: %s", u); return redirect(url_for("index"))
        else:
            _rf(u); logger.warning("登录失败: %s", u); return render_template("login.html",error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("登出: %s", session.get("username")); session.clear(); return redirect(url_for("index"))

# ────────────────────────────────────────────────
#  搜索: f-string 拼接 — 演示6种注入类型
# ────────────────────────────────────────────────
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []; sql_built = ""; inject_type = ""; error_msg = ""; row_count = 0; cond_true = None
    if keyword:
        sql_built = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print("\n[漏洞SQL]", sql_built)
        kw_upper = keyword.upper().replace("%20"," ").replace("+"," ")
        if "UNION SELECT" in kw_upper or "' UNION" in kw_upper: inject_type = "UNION注入"
        elif "' OR '" in kw_upper: inject_type = "OR注入（永真条件）"
        elif "' AND " in kw_upper or "' && " in kw_upper:
            inject_type = "AND布尔盲注"
            cond_true = "'1'='1" in kw_upper or "'1'='1'" in kw_upper or "1=1" in kw_upper.split() or "1=1--" in kw_upper
            if cond_true is None: cond_true = "'1'='2" not in kw_upper and "'2'='2" in kw_upper
        elif "EXTRACTVALUE" in kw_upper or "UPDATEXML" in kw_upper: inject_type = "报错注入"
        elif ";" in keyword: inject_type = "堆叠注入（SQLite限制，实际仅执行首条）"
        elif "%" in keyword and keyword.count("%") >= 2: inject_type = "LIKE通配符注入"
        else: inject_type = "正常搜索"
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor(); c.execute(sql_built); results = c.fetchall(); conn.close()
            row_count = len(results)
        except Exception as e:
            error_msg = str(e); print("[SQL错误]", error_msg)
    u = session.get("username"); ui = None
    if u:
        sql2 = f"SELECT username,email,phone,role,balance FROM users WHERE username='{u}'"
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor(); c.execute(sql2); row = c.fetchone(); conn.close()
            if row: ui = {"username":row[0],"email":row[1],"phone":row[2],"role":row[3],"balance":row[4]}
        except: pass
    return render_template("index.html", username=u, user=ui, search_results=results,
                         keyword=keyword, sql_built=sql_built, inject_type=inject_type,
                         error_msg=error_msg, row_count=row_count, cond_true=cond_true)

# ────────────────────────────────────────────────
#  注册: f-string 拼接 — INSERT注入演示
# ────────────────────────────────────────────────
@app.route("/register", methods=["GET","POST"])
def register():
    sql_built = ""; inject_type = ""; error_msg = ""
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password",""); e = request.form.get("email","").strip(); ph = request.form.get("phone","").strip()
        sql_built = f"INSERT INTO users (username, password, email, phone, role, balance) VALUES ('{u}', '{p}', '{e}', '{ph}', 'user', 0)"
        print("\n[漏洞SQL-INSERT]", sql_built)
        if "'" in u or "'" in p or ")" in u: inject_type = "INSERT注入(SQL字符逃逸)"
        try:
            conn = sqlite3.connect(DB_PATH); c = conn.cursor(); c.execute(sql_built); conn.commit(); conn.close()
            return render_template("login.html", error="注册成功，请登录")
        except Exception as ex:
            error_msg = str(ex); print("[SQL错误]", error_msg)
            return render_template("register.html", error=f"注册失败: {error_msg}",
                                 sql_built=sql_built, inject_type=inject_type)
    return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
