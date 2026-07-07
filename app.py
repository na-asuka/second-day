import os
import re
import secrets
import logging
from time import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, session, url_for
from passlib.hash import bcrypt

# ---------------------------------------------------------------------------
# 日志配置（带轮转，防止磁盘爆满）
# ---------------------------------------------------------------------------
_handler = RotatingFileHandler("login_audit.log", maxBytes=5 * 1024 * 1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[_handler, logging.StreamHandler()],
)
logger = logging.getLogger("auth")

# ---------------------------------------------------------------------------
# Flask 应用 & 安全配置
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "环境变量 SECRET_KEY 未设置。\n"
        "  生成: export SECRET_KEY=$(python3 -c 'import os; print(os.urandom(32).hex())')"
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True if os.environ.get("FORCE_HTTPS") else False,
)
app.permanent_session_lifetime = timedelta(hours=2)

# ---------------------------------------------------------------------------
# 全链路 HTTPS 跳转（当 FORCE_HTTPS 启用时）
# ---------------------------------------------------------------------------
if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _redirect_to_https():
        if not request.is_secure and request.headers.get("X-Forwarded-Proto", "http") != "https":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, 301)

# ---------------------------------------------------------------------------
# CSRF 上下文处理器（每次渲染模板自动注入 csrf_token）
# ---------------------------------------------------------------------------
@app.context_processor
def _inject_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["_csrf_token"]}


def _csrf_validate():
    """验证 POST 请求中的 CSRF 令牌，失败则终止请求。"""
    token = request.form.get("_csrf_token")
    if not token or not secrets.compare_digest(token, session.get("_csrf_token", "")):
        logger.warning("CSRF 校验失败: remote_addr=%s", request.remote_addr)
        return False
    return True


# ---------------------------------------------------------------------------
# 强密码策略
# ---------------------------------------------------------------------------
PASSWORD_MIN_LENGTH = 8

# 密码强度规则：至少包含大写字母、小写字母、数字、特殊符号
PASSWORD_PATTERNS = [
    (r"[A-Z]",       "至少 1 个大写字母"),
    (r"[a-z]",       "至少 1 个小写字母"),
    (r"\d",          "至少 1 个数字"),
    (r"[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?~`]", "至少 1 个特殊符号"),
]


def validate_password_strength(password: str) -> list[str]:
    """校验密码强度，返回所有不满足规则的提示列表，空列表表示通过。"""
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"密码长度不能少于 {PASSWORD_MIN_LENGTH} 位")
    for pattern, hint in PASSWORD_PATTERNS:
        if not re.search(pattern, password):
            errors.append(f"密码必须包含{hint}")
    return errors

# ---------------------------------------------------------------------------
# 使用 bcrypt 哈希库（passlib 封装，计算成本高，抗暴力破解）
# ---------------------------------------------------------------------------
def hash_password(plain: str) -> str:
    return bcrypt.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.verify(plain, hashed)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# 用户数据（生产环境应从数据库读取）
# 敏感配置 / 初始密码通过环境变量注入，杜绝硬编码
# ---------------------------------------------------------------------------
admin_pass = os.environ.get("ADMIN_INIT_PASS")
if not admin_pass:
    raise RuntimeError("环境变量 ADMIN_INIT_PASS 未设置")
alice_pass = os.environ.get("ALICE_INIT_PASS")
if not alice_pass:
    raise RuntimeError("环境变量 ALICE_INIT_PASS 未设置")

USERS = {
    "admin": {
        "username": "admin",
        "password": hash_password(admin_pass),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": hash_password(alice_pass),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ---------------------------------------------------------------------------
# 暴力破解防护（单进程有效；多 worker / 多实例需切换至 Redis）
# 策略：基于 IP + 用户名双层计数
# ---------------------------------------------------------------------------
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOCK_MINUTES = 5
MAX_ATTEMPTS = 5


def _lock_key(username: str) -> str:
    ip = request.remote_addr or "unknown"
    return f"{ip}:{username}"


def _is_locked(username: str) -> bool:
    now = time()
    key = _lock_key(username)
    attempts = LOGIN_ATTEMPTS.get(key, [])
    attempts = [t for t in attempts if now - t < LOCK_MINUTES * 60]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def _record_failure(username: str) -> None:
    key = _lock_key(username)
    LOGIN_ATTEMPTS.setdefault(key, []).append(time())


def _clear_attempts(username: str) -> None:
    key = _lock_key(username)
    LOGIN_ATTEMPTS.pop(key, None)


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # ── CSRF 校验 ──
        if not _csrf_validate():
            return render_template("login.html", error="无效的请求，请刷新页面重试"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ── 暴力破解检测 ──
        if _is_locked(username):
            logger.warning("登录锁定: key=%s", _lock_key(username))
            return render_template("login.html", error=f"尝试次数过多，请{LOCK_MINUTES}分钟后再试")

        # ── 身份校验（bcrypt 验证） ──
        try:
            user = USERS.get(username)
            valid = user is not None and verify_password(password, user["password"])
        except Exception:
            logger.error("密码校验异常: username=%s", username)
            valid = False

        if valid:
            session.permanent = True
            session["username"] = username
            _clear_attempts(username)
            logger.info(
                "登录成功: username=%s role=%s remote_addr=%s",
                username, user["role"], request.remote_addr,
            )
            return redirect(url_for("index"))
        else:
            _record_failure(username)
            logger.warning(
                "登录失败: username=%s remote_addr=%s",
                username, request.remote_addr,
            )
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        logger.info("用户登出: username=%s remote_addr=%s", username, request.remote_addr)
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
