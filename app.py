"""
====================================================================
  安全版 v3.0 — 纵深防御: 水平越权/支付逻辑/垂直越权
  端口: 5000
  功能: 登录/注册/搜索/上传/个人中心/充值/管理后台/URL抓取
====================================================================
"""
import os, re, json, sqlite3, logging, subprocess, platform, urllib.request, urllib.error
import xml.etree.ElementTree as ET
from time import time
from datetime import timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, session, url_for, abort, flash
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
    c.execute("CREATE TABLE IF NOT EXISTS recharges (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount INTEGER, method TEXT, operator_id INTEGER DEFAULT NULL, operator_name TEXT DEFAULT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    try: c.execute("ALTER TABLE recharges ADD COLUMN operator_id INTEGER DEFAULT NULL")
    except: pass
    try: c.execute("ALTER TABLE recharges ADD COLUMN operator_name TEXT DEFAULT NULL")
    except: pass
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
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _https():
        if not request.is_secure: return redirect(request.url.replace("http://","https://",1),301)
@app.after_request
def _headers(r):
    r.headers.update({"X-Frame-Options":"DENY","X-Content-Type-Options":"nosniff"})
    return r

# ── CSRF ──
@app.context_processor
def _inject_globals():
    session.setdefault("_csrf_token", os.urandom(16).hex())
    uid, urole, uname = None, None, session.get("username")
    if uname:
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor()
            c.execute("SELECT id,role FROM users WHERE username=?",(uname,))
            r=c.fetchone();conn.close()
            if r: uid, urole = r[0], r[1]
        except: pass
    return {"csrf_token":session["_csrf_token"],"current_user_id":uid,"current_user_role":urole}

def _csrf_v():
    t = request.form.get("_csrf_token")
    return bool(t and t == session.get("_csrf_token",""))

# ── 辅助函数 ──
def _get_cur():
    """获取当前登录用户(id, username, role)，未登录返回None"""
    uname = session.get("username")
    if not uname: return None
    try:
        conn=sqlite3.connect(DB_PATH);c=conn.cursor()
        c.execute("SELECT id,username,role FROM users WHERE username=?",(uname,))
        r=c.fetchone();conn.close()
        return r
    except: return None

def _get_user_by_id(uid):
    """按ID查询用户公开信息"""
    try:
        conn=sqlite3.connect(DB_PATH);c=conn.cursor()
        c.execute("SELECT id,username,email,phone,balance,role FROM users WHERE id=?",(uid,))
        r=c.fetchone();conn.close()
        return r
    except: return None

def hash_pw(p): return bcrypt.hash(p)
def verify_pw(p, h):
    try: return bcrypt.verify(p, h)
    except: return False

LOGIN_AT={};LOCK_MIN,MAX_AT=5,5
def _lk(u): return f"{request.remote_addr}:{u}"
def _is_lk(u): n=time();k=_lk(u);a=[t for t in LOGIN_AT.get(k,[]) if n-t<LOCK_MIN*60];LOGIN_AT[k]=a;return len(a)>=MAX_AT
def _rf(u): LOGIN_AT.setdefault(_lk(u),[]).append(time())
def _cl(u): LOGIN_AT.pop(_lk(u),None)

# ── Admin 装饰器 ──
def admin_required(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        cur = _get_cur()
        if not cur: return redirect(url_for("login"))
        if cur[2] != "admin": return abort(403)
        return f(*args,**kwargs)
    return wrapper

# ═══════════════════════════════════════════════════════════════
#  首页
# ═══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    cur = _get_cur()
    ui = None
    if cur:
        r = _get_user_by_id(cur[0])
        if r: ui = {"username":r[1],"email":r[2],"phone":r[3],"balance":r[4],"role":r[5]}
    return render_template("index.html", username=cur[1] if cur else None, user=ui)

# ═══════════════════════════════════════════════════════════════
#  登录/登出
# ═══════════════════════════════════════════════════════════════
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not _csrf_v(): return render_template("login.html",error="无效请求"),400
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        if _is_lk(u): return render_template("login.html",error=f"请{LOCK_MIN}分钟后再试")
        valid=False
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?",(u,))
            r=c.fetchone();conn.close()
            if r and verify_pw(p,r[0]): valid=True
        except Exception as e: logger.error("登录异常: %s",e)
        if valid:
            session.permanent=True;session["username"]=u;_cl(u);logger.info("登录: %s",u)
            return redirect(url_for("index"))
        else: _rf(u);logger.warning("登录失败: %s",u);return render_template("login.html",error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("登出: %s",session.get("username"));session.clear();return redirect(url_for("index"))

# ═══════════════════════════════════════════════════════════════
#  搜索（参数化查询）
# ═══════════════════════════════════════════════════════════════
@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword","").strip(); results=[]
    if keyword:
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_val = f"%{keyword}%"
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor();c.execute(sql,(like_val,like_val));results=c.fetchall();conn.close()
        except Exception as e: logger.error("搜索异常: %s",e)
    cur = _get_cur(); ui = None
    if cur:
        r = _get_user_by_id(cur[0])
        if r: ui={"username":r[1],"email":r[2],"phone":r[3],"balance":r[4],"role":r[5]}
    return render_template("index.html", username=cur[1] if cur else None, user=ui, search_results=results, keyword=keyword)

# ═══════════════════════════════════════════════════════════════
#  注册（参数化查询+bcrypt）
# ═══════════════════════════════════════════════════════════════
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        e=request.form.get("email","").strip(); ph=request.form.get("phone","").strip()
        pw_hash = hash_pw(p)
        sql = "INSERT INTO users (username,password,email,phone,role,balance) VALUES (?,?,?,?,'user',0)"
        try:
            conn=sqlite3.connect(DB_PATH);c=conn.cursor();c.execute(sql,(u,pw_hash,e,ph));conn.commit();conn.close()
            return render_template("login.html",error="注册成功，请登录")
        except: return render_template("register.html",error="注册失败")
    return render_template("register.html")

# ═══════════════════════════════════════════════════════════════
#  上传（WAF模拟+CSRF+路径穿越防护）
# ═══════════════════════════════════════════════════════════════
WAF_BLOCKED_EXTS = ('.php','.phtml','.php5','.php7','.php8','.asp','.aspx','.jsp','.html','.htm','.svg','.xml')
WAF_DANGEROUS_PATTERNS = [
    (rb'eval\s*\(','eval'),(rb'system\s*\(','system'),(rb'assert\s*\(','assert'),
    (rb'shell_exec\s*\(','shell_exec'),(rb'exec\s*\(','exec'),(rb'passthru\s*\(','passthru'),
    (rb'\$_POST\s*\[','$_POST'),(rb'\$_GET\s*\[','$_GET'),(rb'\$_REQUEST\s*\[','$_REQUEST'),
    (rb'base64_decode\s*\(','base64_decode'),(rb'create_function\s*\(','create_function'),
]

def simulated_waf(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        if request.method=='POST' and request.path=='/upload':
            uf=request.files.get('file')
            if uf and uf.filename:
                _,ext=os.path.splitext(uf.filename)
                if ext.lower() in WAF_BLOCKED_EXTS: logger.warning("🚫 WAF:恶意扩展名 %s",ext);return abort(403)
                content=uf.read(2048);uf.seek(0)
                for pat,desc in WAF_DANGEROUS_PATTERNS:
                    if re.search(pat,content,re.IGNORECASE): logger.warning("🚫 WAF:%s",desc);return abort(403)
        return f(*args,**kwargs)
    return wrapper

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")

@app.route("/upload", methods=["GET","POST"])
@simulated_waf
def upload():
    if "username" not in session: return redirect(url_for("login"))
    file_url=None;error=None
    if request.method=="POST":
        if not _csrf_v(): return render_template("upload.html",error="无效请求"),400
        f=request.files.get("file")
        if f and f.filename:
            fn=os.path.basename(f.filename)
            if not fn: error="文件名无效"
            else:
                os.makedirs(UPLOAD_FOLDER,exist_ok=True);f.save(os.path.join(UPLOAD_FOLDER,fn))
                file_url=url_for("static",filename=f"uploads/{fn}")
        else: error="请选择文件"
    return render_template("upload.html",file_url=file_url,error=error)

# ═══════════════════════════════════════════════════════════════
#  个人中心（水平越权纵深防御）
#  【防御1】未登录跳转
#  【防御2】默认查看自己的资料（不从URL取session中已有值）
#  【防御3】指定user_id时强制校验session归属
#  【防御4】admin例外可查看全部
# ═══════════════════════════════════════════════════════════════
@app.route("/profile", methods=["GET"])
def profile():
    cur = _get_cur()
    if not cur: return redirect(url_for("login"))
    req_uid = request.args.get("user_id", str(cur[0]))
    # 防御: 普通用户只能看自己, admin可看全部
    if cur[2] != "admin" and str(cur[0]) != req_uid:
        return abort(403)
    r = _get_user_by_id(req_uid)
    user_data = None
    if r:
        user_data = {"id":r[0],"username":r[1],"email":r[2],"phone":r[3],"balance":r[4],"role":r[5]}
    return render_template("profile.html", user=user_data, cur_role=cur[2])

# ═══════════════════════════════════════════════════════════════
#  充值（支付逻辑纵深防御）
#  【防御1】user_id 从 session 获取，不信任客户端传入
#  【防御2】固定套餐金额（服务端映射），不信任客户端传入金额
#  【防御3】金额强制为正整数
#  【防御4】数据库事务 + 排他锁防并发
#  【防御5】充值记录写入 audit 表（含操作人）
#  【防御6】CSRF 校验
#  【防御7】频率限制：同一用户每10秒最多充值1次
# ═══════════════════════════════════════════════════════════════
RECHARGE_PLANS = {10: "10元", 50: "50元", 100: "100元", 500: "500元"}
RECHARGE_COOLDOWN = {}  # uid -> last_timestamp

@app.route("/recharge", methods=["POST"])
def recharge():
    cur = _get_cur()
    if not cur: return redirect(url_for("login"))
    if not _csrf_v(): return "无效请求", 400

    uid = cur[0]

    # 防御7: 频率限制
    now = time()
    last = RECHARGE_COOLDOWN.get(uid, 0)
    if now - last < 10:
        logger.warning("充值频率过高: uid=%s", uid)
        return redirect(url_for("profile", user_id=uid))
    RECHARGE_COOLDOWN[uid] = now

    # 防御2: 金额只能从套餐映射表取值
    plan = request.form.get("plan")
    try: plan = int(plan)
    except: return redirect(url_for("profile", user_id=uid))
    if plan not in RECHARGE_PLANS:
        return redirect(url_for("profile", user_id=uid))
    amount = int(plan)
    # 防御3: 金额强制为正整数
    if amount <= 0:
        return redirect(url_for("profile", user_id=uid))

    # 防御4: 事务+排他锁，防并发
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("BEGIN EXCLUSIVE")
        c.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, uid))
        c.execute("INSERT INTO recharges (user_id, amount, method, operator_id, operator_name) VALUES (?, ?, '套餐', ?, ?)", (uid, amount, uid, cur[1]))
        conn.commit()
        conn.close()
        logger.info("充值成功: uid=%s amount=%s plan=%s", uid, amount, plan)
    except Exception as e:
        logger.error("充值事务异常: %s", e)
    return redirect(url_for("profile", user_id=uid))

# ═══════════════════════════════════════════════════════════════
#  管理后台（垂直越权纵深防御）
#  【防御1】@admin_required 装饰器
#  【防御2】普通用户访问返回 403
#  【防御3】后台功能仅admin可见
# ═══════════════════════════════════════════════════════════════
@app.route("/admin")
@admin_required
def admin_dashboard():
    try:
        conn=sqlite3.connect(DB_PATH);c=conn.cursor()
        c.execute("SELECT COUNT(*) FROM users"); total_users=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE role='admin'"); admin_count=c.fetchone()[0]
        c.execute("SELECT SUM(balance) FROM users"); total_balance=c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM recharges"); total_recharges=c.fetchone()[0]
        c.execute("SELECT SUM(amount) FROM recharges"); recharge_sum=c.fetchone()[0] or 0
        c.execute("SELECT id,username,email,phone,role,balance FROM users ORDER BY id")
        users=c.fetchall()
        conn.close()
    except Exception as e:
        logger.error("管理后台异常: %s",e); return "系统异常",500
    return render_template("admin.html", total_users=total_users, admin_count=admin_count,
                         total_balance=total_balance, total_recharges=total_recharges,
                         recharge_sum=recharge_sum, users=users, RECHARGE_PLANS=RECHARGE_PLANS)

@app.route("/admin/recharge", methods=["POST"])
@admin_required
def admin_recharge():
    if not _csrf_v(): return "无效请求", 400
    uid = request.form.get("user_id")
    plan = request.form.get("plan")
    try: plan = int(plan)
    except: return redirect(url_for("admin_dashboard"))
    if not uid or plan not in RECHARGE_PLANS:
        return redirect(url_for("admin_dashboard"))
    amount = int(plan)
    # 在事务前获取操作人信息（避免EXCLUSIVE锁阻塞第二次查询）
    cur_op = _get_cur()
    op_id = cur_op[0] if cur_op else None
    op_name = cur_op[1] if cur_op else None
    try:
        conn=sqlite3.connect(DB_PATH);c=conn.cursor()
        c.execute("BEGIN EXCLUSIVE")
        c.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, uid))
        c.execute("INSERT INTO recharges (user_id,amount,method,operator_id,operator_name) VALUES (?,?,'管理员充值',?,?)", (uid,amount,op_id,op_name))
        conn.commit();conn.close()
        logger.info("管理员充值: admin=%s target=%s amount=%s", session.get("username"), uid, amount)
    except Exception as e:
        logger.error("管理充值异常: %s",e)
    return redirect(url_for("admin_dashboard"))


@app.route("/page", methods=["GET"])
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    page_name = None

    # 白名单：只允许预设页面
    ALLOWED_PAGES = {"help", "about", "contact"}
    if name in ALLOWED_PAGES:
        base_path = os.path.join(app.root_path, "pages")
        file_path = os.path.join(base_path, name + ".html")
        # 路径规范化校验：确保目标在 pages/ 目录下
        real_path = os.path.realpath(file_path)
        pages_dir = os.path.realpath(base_path)
        if real_path.startswith(pages_dir) and os.path.isfile(real_path):
            with open(real_path, "r", encoding="utf-8") as f:
                page_content = f.read()
            page_name = name + ".html"
        else:
            page_content = "页面不存在"
    else:
        page_content = "页面不存在"
    return render_template("page.html", page_content=page_content, page_name=page_name)


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect(url_for("login"))
    if not _csrf_v():
        return "无效请求", 400
    target_url = request.form.get("url", "").strip()
    status_code = None
    content_preview = None
    error_msg = None

    if target_url:
        # 防御1: 协议白名单 — 仅允许 http/https
        parsed = urllib.request.urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            logger.warning("SSRF阻断: 非法协议 scheme=%s url=%s user=%s", parsed.scheme, target_url, session.get("username"))
            error_msg = "不支持的协议（仅允许 http/https）"
            return render_template("fetch_result.html", url=target_url, status_code=None, content_preview=None, error_msg=error_msg)

        # 防御2: 私有 IP 拦截（DNS 解析前校验）
        import socket
        hostname = parsed.hostname
        try:
            # DNS 解析
            ip = socket.gethostbyname(hostname)
        except Exception:
            error_msg = "无法解析目标域名"
            return render_template("fetch_result.html", url=target_url, status_code=None, content_preview=None, error_msg=error_msg)

        # 私有 IP 地址段
        def _is_private_ip(ip_addr):
            import ipaddress
            try:
                addr = ipaddress.ip_address(ip_addr)
                return addr.is_private
            except ValueError:
                return True  # 无法解析的 IP 当作私有处理

        if _is_private_ip(ip):
            logger.warning("SSRF阻断: 内网IP ip=%s host=%s url=%s user=%s", ip, hostname, target_url, session.get("username"))
            error_msg = "不允许访问内网地址"
            return render_template("fetch_result.html", url=target_url, status_code=None, content_preview=None, error_msg=error_msg)

        # 防御3: DNS 解析后二次校验（防御 DNS 重绑定）
        try:
            ip2 = socket.gethostbyname(hostname)
            if ip != ip2 or _is_private_ip(ip2):
                logger.warning("SSRF阻断: DNS重绑定检测 ip=%s ip2=%s host=%s", ip, ip2, hostname)
                error_msg = "目标地址不合法"
                return render_template("fetch_result.html", url=target_url, status_code=None, content_preview=None, error_msg=error_msg)
        except Exception:
            error_msg = "目标地址解析异常"
            return render_template("fetch_result.html", url=target_url, status_code=None, content_preview=None, error_msg=error_msg)

        # 防御4: 禁止自动跟随重定向（防止重定向到内网绕过 IP 黑名单）
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                logger.warning("SSRF阻断: 禁止重定向 from=%s to=%s", req.full_url, newurl)
                return None  # 拒绝跟随重定向

        try:
            opener = urllib.request.build_opener(NoRedirectHandler)
            req = urllib.request.Request(target_url)
            with opener.open(req, timeout=10) as resp:
                status_code = resp.status
                raw = resp.read()
                content_preview = raw.decode("utf-8", errors="replace")[:5000]
                logger.info("URL抓取: target=%s status=%s user=%s", target_url, status_code, session.get("username"))
        except urllib.error.HTTPError as e:
            status_code = e.code
            content_preview = str(e)[:5000]
        except Exception as e:
            error_msg = str(e)[:500]

    return render_template("fetch_result.html", url=target_url, status_code=status_code,
                         content_preview=content_preview, error_msg=error_msg)


@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))
    if not _csrf_v():
        return "无效请求", 400

    target_user = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    session_user = session.get("username", "")

    # 获取当前用户 ID（用于重定向）
    session_uid = None
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (session_user,))
        r = c.fetchone()
        if r: session_uid = r[0]
        conn.close()
    except: pass

    # 防御: 空值校验
    if not target_user or not new_password:
        flash("用户名或密码不能为空", "error")
        return redirect(url_for("profile", user_id=session_uid or session_user))

    # 防御: 确认密码校验
    if new_password != confirm_password:
        flash("两次输入的密码不一致", "error")
        return redirect(url_for("profile", user_id=session_uid or session_user))

    # 防御: session归属校验 — 只能改自己密码
    if target_user != session_user:
        return abort(403)

    uid = None
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hash_pw(new_password), target_user))
        conn.commit()
        c.execute("SELECT id FROM users WHERE username = ?", (target_user,))
        r = c.fetchone()
        if r: uid = r[0]
        conn.close()
        logger.info("密码修改: target=%s operator=%s", target_user, session_user)
    except Exception as e:
        logger.error("密码修改异常: %s", e)
    if uid:
        return redirect(url_for("profile", user_id=uid))
    return redirect(url_for("index"))


# ── 合法的 IP/域名白名单正则（防止命令注入） ──
import re as _re
PING_ALLOWED = _re.compile(r'^[a-zA-Z0-9.\-]+$')

@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect(url_for("login"))
    result = None
    ip = ""
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            # 措施2: 白名单输入验证 — 仅允许合法IP/域名，拒绝特殊字符
            if not PING_ALLOWED.match(ip) or ".." in ip or ip.startswith("-"):
                logger.warning("命令注入拦截: ip=%s user=%s remote_addr=%s", ip, session.get("username"), request.remote_addr)
                result = "无效的 IP 地址或域名（包含非法字符）"
            else:
                logger.info("Ping执行: ip=%s user=%s", ip, session.get("username"))
                try:
                    # 措施1: 参数化执行 — 禁用 shell=True
                    output = subprocess.check_output(["ping", "-c", "3", ip], stderr=subprocess.STDOUT, timeout=30)
                    result = output.decode("utf-8", errors="replace")
                except subprocess.TimeoutExpired:
                    result = "Ping 超时 (30秒)"
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace") if e.output else "Ping 失败"
                except Exception as e:
                    result = f"执行错误: {e}"
    return render_template("ping.html", result=result, ip=ip)


# ── 允许通过实体引用的本地文件白名单路径 ──
XXE_ALLOWED_PATHS = [
    os.path.join(app.root_path, "data"),
]

def _xxe_allowed(filepath):
    real = os.path.realpath(filepath)
    for base in XXE_ALLOWED_PATHS:
        base_real = os.path.realpath(base)
        # 加后缀分隔符，防止 data 匹配到 data_evil
        base_prefix = base_real if base_real.endswith(os.sep) else base_real + os.sep
        if real == base_real or real.startswith(base_prefix):
            return True
    return False

@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if "username" not in session:
        return redirect(url_for("login"))
    result = None
    error = None
    xml_data = ""
    if request.method == "POST":
        xml_data = request.form.get("xml_data", "").strip()
        if xml_data:
            # 检测 <!ENTITY 和 SYSTEM 关键字
            if "<!ENTITY" in xml_data and "SYSTEM" in xml_data:
                # 提取 SYSTEM 后面的文件路径
                match = re.search(r'<!ENTITY\s+\w+\s+SYSTEM\s+"([^"]+)"', xml_data)
                if match:
                    file_path = match.group(1)
                    # 白名单校验：只允许读取指定目录下的文件
                    if not _xxe_allowed(file_path):
                        logger.warning("XXE阻断: 非法文件路径 path=%s user=%s remote_addr=%s",
                                       file_path, session.get("username"), request.remote_addr)
                        error = f"不允许读取该文件"
                    else:
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                                file_content = f.read()
                            entity_name = re.search(r'<!ENTITY\s+(\w+)\s+SYSTEM', xml_data).group(1)
                            xml_data = xml_data.replace(f"&{entity_name};", file_content)
                        except Exception as e:
                            error = f"无法读取文件 {file_path}: {e}"
            try:
                root = ET.fromstring(xml_data)
                users = []
                for user_elem in root.findall("user"):
                    name = user_elem.findtext("name", "")
                    email = user_elem.findtext("email", "")
                    users.append({"name": name, "email": email})
                result = json.dumps(users, indent=2, ensure_ascii=False)
                logger.info("XML导入成功: user=%s count=%d", session.get("username"), len(users))
            except ET.ParseError as e:
                error = f"XML 解析错误: {e}"
            except Exception as e:
                error = f"处理错误: {e}"
    return render_template("xml_import.html", result=result, error=error, xml_data=xml_data)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
