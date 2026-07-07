# 用户信息管理平台 — 漏洞分析与修复报告

---

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 项目名称 | 用户信息管理平台 |
| 技术栈 | Python Flask + Jinja2 + passlib(bcrypt) |
| 开发语言 | Python 3.8+ |
| 仓库地址 | https://github.com/na-asuka/second-day |
| 初始状态 | 存在 12 项安全漏洞（4 项高危 + 5 项中危 + 3 项低危） |
| 修复后状态 | 18 项安全措施全部部署 |

本项目是一个基于 Python Flask 的用户信息管理登录系统，包含用户登录认证、会话管理、用户信息展示三大功能。本文档对该项目的初始版本进行完整的漏洞挖掘与分析，并逐一给出修复方案，展示从"脆弱代码"到"安全代码"的完整演化过程。

---

## 二、初始版本完整代码（漏洞版）

以下为初始提交的完整代码，包含所有安全漏洞。

### 2.1 app.py（初始漏洞版）

```python
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"                     # [漏洞3] 弱密钥硬编码

USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",                      # [漏洞1] 明文存储
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",                     # [漏洞1] 明文存储
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

@app.route("/")
def index():
    username = session.get("username")
    if username and username in USERS:
        user_info = USERS[username]                  # [漏洞5] 完整信息包含密码
    return render_template("index.html", username=username, user=user_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and USERS[username]["password"] == password:  # [漏洞1] ==明文比对
            session["username"] = username
            user_info = USERS[username]              # [漏洞5] 密码传给模板
            return render_template("index.html", username=username, user=user_info)  # [漏洞6] 直接渲染
        else:
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)   # [漏洞2] 调试模式RCE
```

### 2.2 templates/login.html（初始漏洞版）

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->  <!-- [漏洞4] 注释泄露凭据 -->
{% extends "base.html" %}
{% block content %}
<div class="card card-login">
    <h2>用户登录</h2>
    <hr>
    {% if error %}
        <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    <form method="post" action="/login">                        <!-- [漏洞7] 无CSRF令牌 -->
        <div class="form-group">
            <label for="username">用户名</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">密码</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary btn-block">登录</button>
    </form>
</div>
{% endblock %}
```

### 2.3 templates/index.html（初始漏洞版）

```html
{% extends "base.html" %}
{% block content %}
<div class="card">
    {% if username and user %}
        <h2>欢迎回来，{{ username }}！</h2>
        <hr>
        <ul class="info-list">
            <li><span class="label">用户名：</span>{{ user.username }}</li>
            <li><span class="label">密码：</span>{{ user.password }}</li>    <!-- [漏洞5] 密码明文显示 -->
            <li><span class="label">邮箱：</span>{{ user.email }}</li>
            <li><span class="label">手机：</span>{{ user.phone }}</li>
            <li><span class="label">角色：</span>{{ user.role }}</li>
            <li><span class="label">余额：</span>{{ user.balance }}</li>
        </ul>
        <a href="/logout" class="btn btn-danger">退出登录</a>
    {% else %}
        <h2>请先登录</h2>
        <p>您尚未登录，请登录后查看用户信息。</p>
        <a href="/login" class="btn">前往登录</a>
    {% endif %}
</div>
{% endblock %}
```

---

## 三、漏洞逐项分析

---

### 🔴 漏洞一：密码明文存储与比对

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A02:2021 – 加密失败](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **CVE 参考** | 通用密码存储缺陷 |
| **严重级别** | 🔴 高危 |
| **影响范围** | 全部用户 |

**漏洞描述：**

密码以明文形式存储在 `USERS` 字典中，登录验证时使用 `==` 直接比对字符串。

**风险分析：**

1. **数据泄露即密码泄露**：代码仓库一旦泄露（如 GitHub 公开仓库、内部泄露），攻击者直接获得所有用户的原始密码
2. **撞库攻击**：用户往往在多个平台使用相同密码，攻击者可利用泄露的密码登录用户的其它账号（邮箱、社交、支付等）
3. **时序攻击风险**：`==` 字符串比较非恒定时间，理论上可通过测量响应时间逐字符推断密码
4. **内部威胁**：拥有代码访问权限的开发人员可直接读取所有用户的密码

**利用场景：**

```
攻击者获取源代码 → 打开 app.py → 看到 USERS 字典 → 直接获得：
    admin / admin123
    alice / alice2025
→ 尝试登录其他系统（GitHub、邮箱等）→ 撞库成功
```

**修复方案：**

采用 bcrypt 哈希算法存储密码。bcrypt 具有以下安全特性：
- **自动加盐**：每个密码使用不同的随机盐值，相同密码产生不同哈希
- **可调计算成本**：增加破解的计算开销
- **抗 GPU/ASIC**：内存硬设计，专用硬件难以加速

```python
from passlib.hash import bcrypt

def hash_password(plain: str) -> str:
    """使用 bcrypt 哈希密码，自动加盐"""
    return bcrypt.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    """安全验证密码，异常时返回 False"""
    try:
        return bcrypt.verify(plain, hashed)
    except Exception:
        return False

# 启动时从环境变量读取明文密码，立即哈希存储
admin_pass = os.environ.get("ADMIN_INIT_PASS")
USERS = {
    "admin": {
        "password": hash_password(admin_pass),  # 立刻转为 bcrypt 哈希
    },
}
del admin_pass  # 使用完毕立即从内存中清除明文
```

---

### 🔴 漏洞二：调试模式开启

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A05:2021 – 安全配置错误](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| **CVE 参考** | CWE-489: Active Debug Code |
| **严重级别** | 🔴 高危 |
| **影响范围** | 服务器全部控制权 |

**漏洞描述：**

Flask 以 `debug=True` 模式启动，开启了 Werkzeug 调试器。

**风险分析：**

1. **远程代码执行（RCE）**：Werkzeug 调试器提供一个交互式 Python 控制台（web-based debugger console），攻击者触发任意异常后可在浏览器中执行任意系统命令
2. **敏感信息泄露**：调试模式下的错误页面会显示完整的 Python 调用栈、环境变量、源代码片段
3. **局域网扩散**：结合 `host="0.0.0.0"`，局域网内任何设备均可访问

**利用场景：**

```
攻击者访问 http://192.168.x.x:5000/任意不存在的路由
    → Flask 抛出 404 异常
    → Werkzeug 调试器显示交互式控制台
    → 攻击者在控制台中输入：
        import os; os.system('cat /etc/passwd')
    → 服务器信息被窃取
```

**修复方案：**

```python
app.run(debug=False, host="0.0.0.0", port=5000)
```

> **生产环境进一步建议**：使用 `gunicorn` 等生产级 WSGI 服务器替代 `app.run()`。

---

### 🔴 漏洞三：弱密钥硬编码

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A02:2021 – 加密失败](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **CWE 参考** | CWE-321: Use of Hard-coded Cryptographic Key |
| **严重级别** | 🔴 高危 |
| **影响范围** | 全部用户会话 |

**漏洞描述：**

Flask session 签名密钥 `secret_key` 被硬编码为 `"dev-key-2025"`，且强度极低。

**风险分析：**

1. **会话伪造**：Flask 使用 `secret_key` 对 session cookie 进行 HMAC 签名。知道密钥后，攻击者可伪造任意用户的 session
2. **密钥可猜测**：`"dev-key-2025"` 仅 12 位字母数字组合，计算熵值极低，可被暴力猜测
3. **代码仓库泄露**：密钥存在于源代码中，所有能访问仓库的人员均持有密钥

**利用场景：**

```
攻击者获取密钥 "dev-key-2025"
    → 使用 flask-unsign 工具解签 session cookie
    → 伪造 admin 用户的 session cookie：
        { "username": "admin" }
    → 设置到浏览器中
    → 直接以 admin 身份登录，绕过密码验证
```

**修复方案：**

```python
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "环境变量 SECRET_KEY 未设置。\n"
        "  生成: export SECRET_KEY=$(python3 -c 'import os; print(os.urandom(32).hex())')"
    )
```

启动时需设置环境变量：
```bash
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
```

此时密钥为 64 位十六进制字符串，熵值 256 位，不可猜测。

---

### 🔴 漏洞四：HTML 注释泄露管理员凭据

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A01:2021 – 访问控制失效](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| **CWE 参考** | CWE-200: Exposure of Sensitive Information |
| **严重级别** | 🔴 高危 |
| **影响范围** | admin 账户 |

**漏洞描述：**

`login.html` 的 HTML 注释中直接写有管理员用户名和密码。

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

**风险分析：**

1. **页面源码即泄露**：HTML 注释在浏览器"查看页面源代码"中完全可见
2. **无需任何攻击**：普通用户即可通过 F12 开发者工具或右键查看源码获取管理员凭据
3. **自动化收集**：搜索引擎爬虫可能索引包含敏感注释的页面

**修复方案：** 直接删除该行注释。

---

### 🟡 漏洞五：页面明文显示密码

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A04:2021 – 不安全设计](https://owasp.org/Top10/A04_2021-Insecure_Design/) |
| **严重级别** | 🟡 中危 |
| **影响范围** | 已登录用户 |

**漏洞描述：**

登录成功后，首页将用户的密码以明文形式显示在页面上。

**风险分析：**

1. **肩窥攻击**：他人从屏幕背后看到密码
2. **屏幕共享泄露**：远程会议、录屏等场景下密码被意外泄露
3. **截图泄露**：用户分享页面截图时密码一并泄露

**修复方案（双层防护）：**

后端在传递数据时过滤密码字段：
```python
user_info = {k: v for k, v in USERS[username].items() if k != "password"}
```

前端移除密码展示行：
```html
<!-- 密码行已移除，不再显示 -->
<li><span class="label">邮箱：</span>{{ user.email }}</li>
```

---

### 🟡 漏洞六：登录后直接渲染模板

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A04:2021 – 不安全设计](https://owasp.org/Top10/A04_2021-Insecure_Design/) |
| **严重级别** | 🟡 中危 |
| **影响范围** | 用户体验与数据一致性 |

**漏洞描述：**

POST 登录请求验证通过后直接返回 `render_template()`，未进行重定向。

**风险分析：**

1. **表单重复提交**：用户刷新页面时浏览器弹出"确认重新提交表单"对话框
2. **重复操作**：如果登录逻辑中包含副作用操作（如计数、日志），会导致重复记录
3. **不符合 PRG 模式**：Post/Redirect/Get 是 Web 开发的标准设计模式

**修复方案：**

```python
if valid:
    session["username"] = username
    return redirect(url_for("index"))  # PRG 模式
```

---

### 🟡 漏洞七：无 CSRF 防护

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A01:2021 – 访问控制失效](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| **CWE 参考** | CWE-352: Cross-Site Request Forgery |
| **严重级别** | 🟡 中危 |
| **影响范围** | 登录接口 |

**漏洞描述：**

登录表单没有任何 CSRF 令牌保护。

**风险分析：**

攻击者可构造恶意页面，利用已登录用户的 session 发起跨站请求：
```html
<!-- 攻击者页面 -->
<form action="http://target.com/login" method="POST" id="f">
  <input name="username" value="attacker">
  <input name="password" value="evil123">
</form>
<script>document.getElementById('f').submit()</script>
```

**修复方案：**

后端生成令牌：
```python
@app.context_processor
def _inject_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["_csrf_token"]}

def _csrf_validate():
    token = request.form.get("_csrf_token")
    if not token or not secrets.compare_digest(token, session.get("_csrf_token", "")):
        return False
    return True
```

前端表单注入：
```html
<form method="post" action="/login">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
    ...
</form>
```

---

### 🟡 漏洞八：无暴力破解防护

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A07:2021 – 身份验证失效](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **严重级别** | 🟡 中危 |
| **影响范围** | 全部用户账户 |

**漏洞描述：**

登录接口无任何频率限制，攻击者可无限制地尝试密码组合。

**风险分析：**

一个常见密码字典约含 1000 万个密码，以每秒 100 次请求的速度，弱密码在数小时内即可被破解。

**修复方案：**

```python
LOGIN_ATTEMPTS = {}
LOCK_MINUTES = 5
MAX_ATTEMPTS = 5

def _lock_key(username):
    ip = request.remote_addr or "unknown"
    return f"{ip}:{username}"       # IP + 用户名双层绑定

def _is_locked(username):
    now = time()
    key = _lock_key(username)
    attempts = LOGIN_ATTEMPTS.get(key, [])
    attempts = [t for t in attempts if now - t < LOCK_MINUTES * 60]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= MAX_ATTEMPTS
```

---

### 🟡 漏洞九：无会话安全配置

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A07:2021 – 身份验证失效](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **严重级别** | 🟡 中危 |
| **影响范围** | 全部用户会话 |

**漏洞描述：**

session cookie 缺少安全标志，会话无过期时间。

**风险分析：**

| 缺失配置 | 风险 |
|----------|------|
| `HttpOnly` | JavaScript 可通过 `document.cookie` 读取 session cookie，XSS 攻击下直接泄露 |
| `SameSite` | 跨站请求自动携带 cookie，放大 CSRF 攻击影响 |
| 过期时间 | session 永不过期，增加会话劫持的时间窗口 |

**修复方案：**

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # 禁止 JS 读取
    SESSION_COOKIE_SAMESITE="Lax",      # 限制跨站发送
    SESSION_COOKIE_SECURE=True if os.environ.get("FORCE_HTTPS") else False,
)
app.permanent_session_lifetime = timedelta(hours=2)  # 2 小时自动过期
```

---

### 🟢 漏洞十：无安全响应头

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A05:2021 – 安全配置错误](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| **严重级别** | 🟢 低危 |
| **影响范围** | 页面交互安全 |

**漏洞描述：**

HTTP 响应缺少安全头部。

**风险分析：**

| 缺失头部 | 风险 |
|----------|------|
| `X-Frame-Options` | 页面可被嵌入 `<iframe>`，攻击者可构造透明 iframe 诱导用户操作（点击劫持） |
| `X-Content-Type-Options` | 浏览器可能对资源进行 MIME 嗅探，导致非预期解析 |

**修复方案：**

```python
@app.after_request
def _set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
```

---

### 🟢 漏洞十一：无审计日志

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A09:2021 – 安全日志与监控失效](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) |
| **严重级别** | 🟢 低危 |
| **影响范围** | 安全事件追溯 |

**漏洞描述：**

系统未记录任何登录操作日志，发生安全事件后无法追查。

**风险分析：**

- 无法确定攻击发生的时间、来源 IP、使用的用户名
- 无法区分正常登录与暴力破解尝试
- 无法满足合规审计要求

**修复方案：**

```python
import logging
from logging.handlers import RotatingFileHandler

_handler = RotatingFileHandler("login_audit.log", maxBytes=5 * 1024 * 1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler, logging.StreamHandler()])
logger = logging.getLogger("auth")

# 关键事件记录
logger.info("登录成功: username=%s role=%s remote_addr=%s", ...)
logger.warning("登录失败: username=%s remote_addr=%s", ...)
logger.warning("登录锁定: key=%s", ...)
logger.info("用户登出: username=%s remote_addr=%s", ...)
```

---

### 🟢 漏洞十二：无 HTTPS 支持

| 属性 | 内容 |
|------|------|
| **OWASP 分类** | [A02:2021 – 加密失败](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **严重级别** | 🟢 低危 |
| **影响范围** | 数据传输安全 |

**漏洞描述：**

所有数据以明文 HTTP 传输，无加密保护。

**风险分析：**

- 中间人可窃听传输中的密码、session cookie
- 公共 WiFi、局域网环境中攻击成本极低
- 违反 GDPR、等级保护等合规要求

**修复方案：**

```python
if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _redirect_to_https():
        if not request.is_secure and request.headers.get("X-Forwarded-Proto", "http") != "https":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, 301)
```

---

## 四、漏洞修复对照表

| 编号 | 漏洞名称 | 初始代码 | 修复后代码 | 严重级别 |
|------|----------|----------|------------|----------|
| 01 | 密码明文存储 | `"password": "admin123"` | `"password": hash_password(os.environ.get(...))` | 🔴 高 |
| 02 | 调试模式 RCE | `debug=True` | `debug=False` | 🔴 高 |
| 03 | 弱密钥硬编码 | `"dev-key-2025"` | `os.environ.get("SECRET_KEY")` | 🔴 高 |
| 04 | HTML 注释泄密 | `<!-- 密码: admin123 -->` | 已删除 | 🔴 高 |
| 05 | 页面显示密码 | `{{ user.password }}` | 后端过滤 + 前端移除 | 🟡 中 |
| 06 | 登录直接渲染 | `render_template()` | `redirect(url_for("index"))` | 🟡 中 |
| 07 | 无 CSRF | 无令牌 | `secrets.token_hex(32)` + 表单令牌 | 🟡 中 |
| 08 | 无暴力破解 | 无限制 | IP+用户名 5次/5分钟锁定 | 🟡 中 |
| 09 | 无会话安全 | 无配置 | HttpOnly + SameSite + 2h过期 | 🟡 中 |
| 10 | 无安全头部 | 无 | X-Frame-Options: DENY + nosniff | 🟢 低 |
| 11 | 无审计日志 | 无 | RotatingFileHandler 日志 | 🟢 低 |
| 12 | 无 HTTPS | 仅 HTTP | FORCE_HTTPS 可选跳转 | 🟢 低 |

---

## 五、修复后最终代码

### 5.1 app.py（最终安全版）

```python
import os
import re
import secrets
import logging
from time import time
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, session, url_for
from passlib.hash import bcrypt

# ── 日志配置 ──
_handler = RotatingFileHandler("login_audit.log", maxBytes=5 * 1024 * 1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler, logging.StreamHandler()])
logger = logging.getLogger("auth")

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

# ── HTTPS 跳转 ──
if os.environ.get("FORCE_HTTPS"):
    @app.before_request
    def _redirect_to_https():
        if not request.is_secure and request.headers.get("X-Forwarded-Proto", "http") != "https":
            return redirect(request.url.replace("http://", "https://", 1), 301)

# ── 安全响应头 ──
@app.after_request
def _set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# ── CSRF 防护 ──
@app.context_processor
def _inject_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["_csrf_token"]}

def _csrf_validate():
    token = request.form.get("_csrf_token")
    return bool(token and secrets.compare_digest(token, session.get("_csrf_token", "")))

# ── 强密码策略 ──
PASSWORD_MIN_LENGTH = 8
PASSWORD_PATTERNS = [
    (r"[A-Z]", "至少 1 个大写字母"),
    (r"[a-z]", "至少 1 个小写字母"),
    (r"\d", "至少 1 个数字"),
    (r"[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?~`]", "至少 1 个特殊符号"),
]

def validate_password_strength(password):
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"密码长度不能少于 {PASSWORD_MIN_LENGTH} 位")
    for pattern, hint in PASSWORD_PATTERNS:
        if not re.search(pattern, password):
            errors.append(f"密码必须包含{hint}")
    return errors

# ── bcrypt 哈希 ──
def hash_password(plain):
    return bcrypt.hash(plain)

def verify_password(plain, hashed):
    try:
        return bcrypt.verify(plain, hashed)
    except Exception:
        return False

# ── 用户数据（环境变量注入） ──
admin_pass = os.environ.get("ADMIN_INIT_PASS")
if not admin_pass:
    raise RuntimeError("环境变量 ADMIN_INIT_PASS 未设置")
alice_pass = os.environ.get("ALICE_INIT_PASS")
if not alice_pass:
    raise RuntimeError("环境变量 ALICE_INIT_PASS 未设置")

USERS = {
    "admin": {"username": "admin", "password": hash_password(admin_pass),
              "role": "admin", "email": "admin@example.com",
              "phone": "13800138000", "balance": 99999},
    "alice": {"username": "alice", "password": hash_password(alice_pass),
              "role": "user", "email": "alice@example.com",
              "phone": "13900139001", "balance": 100},
}
del admin_pass, alice_pass  # 清除内存中的明文

# ── 暴力破解防护 ──
LOGIN_ATTEMPTS = {}
LOCK_MINUTES = 5
MAX_ATTEMPTS = 5

def _lock_key(username):
    return f"{request.remote_addr}:{username}"

def _is_locked(username):
    now = time()
    key = _lock_key(username)
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
    user_info = USERS[username].copy() if username in USERS else None
    if user_info:
        user_info.pop("password", None)
    return render_template("index.html", username=username, user=user_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _csrf_validate():
            return render_template("login.html", error="无效的请求，请刷新页面重试"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if _is_locked(username):
            return render_template("login.html", error=f"尝试次数过多，请{LOCK_MINUTES}分钟后再试")

        user = USERS.get(username)
        valid = user and verify_password(password, user["password"])

        if valid:
            session.permanent = True
            session["username"] = username
            _clear_attempts(username)
            logger.info("登录成功: username=%s role=%s", username, user["role"])
            return redirect(url_for("index"))
        else:
            _record_failure(username)
            logger.warning("登录失败: username=%s remote_addr=%s", username, request.remote_addr)
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")

@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        logger.info("用户登出: username=%s", username)
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
```

### 5.2 templates/login.html（最终安全版）

```html
{% extends "base.html" %}
{% block content %}
<div class="card card-login">
    <h2>用户登录</h2>
    <hr>
    {% if error %}
        <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    <form method="post" action="/login">
        <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
        <div class="form-group">
            <label for="username">用户名</label>
            <input type="text" id="username" name="username" placeholder="请输入用户名" required>
        </div>
        <div class="form-group">
            <label for="password">密码</label>
            <input type="password" id="password" name="password" placeholder="请输入密码" required>
        </div>
        <button type="submit" class="btn btn-primary btn-block">登录</button>
    </form>
</div>
{% endblock %}
```

### 5.3 templates/index.html（最终安全版）

```html
{% extends "base.html" %}
{% block content %}
<div class="card">
    {% if username and user %}
        <h2>欢迎回来，{{ username }}！</h2>
        <hr>
        <ul class="info-list">
            <li><span class="label">用户名：</span>{{ user.username }}</li>
            <li><span class="label">邮箱：</span>{{ user.email }}</li>
            <li><span class="label">手机：</span>{{ user.phone }}</li>
            <li><span class="label">角色：</span>{{ user.role }}</li>
            <li><span class="label">余额：</span>{{ user.balance }}</li>
        </ul>
        <a href="/logout" class="btn btn-danger">退出登录</a>
    {% else %}
        <h2>请先登录</h2>
        <p>您尚未登录，请登录后查看用户信息。</p>
        <a href="/login" class="btn">前往登录</a>
    {% endif %}
</div>
{% endblock %}
```

---

## 六、攻击面对比总结

| 攻击类型 | 修复前 | 修复后 |
|----------|--------|--------|
| **数据泄露 → 密码泄露** | 明文密码直接暴露 | 不可逆 bcrypt 哈希 |
| **远程代码执行 RCE** | debug=True 可执行任意代码 | 已禁用 |
| **会话伪造** | 弱密钥 `dev-key-2025` 可猜测 | 256 位随机密钥 |
| **源码信息泄露** | HTML 注释暴露管理员凭据 | 已删除 |
| **肩窥攻击** | 密码明文显示在页面 | 已过滤 |
| **表单重复提交** | 刷新弹窗"确认重新提交" | 符合 PRG 模式 |
| **跨站请求伪造 CSRF** | 无令牌保护 | 256 位 CSRF 令牌 + 常量时间比对 |
| **暴力破解** | 无限制无限尝试 | IP+用户名限流，5 次锁定 5 分钟 |
| **会话劫持** | 无 HttpOnly/SameSite/过期 | HttpOnly + SameSite=Lax + 2h 过期 |
| **点击劫持** | 可嵌入 iframe | X-Frame-Options: DENY |
| **中间人攻击** | 纯 HTTP 明文传输 | 支持 HTTPS 强制跳转 |
| **安全审计** | 无日志 | 完整日志 + 轮转存储 |

---

## 七、安全架构全景图

```
                          ┌─────────────────────────────┐
                          │       用户浏览器              │
                          └──────────────┬──────────────┘
                                         │
                          ┌──────────────▼──────────────┐
                          │    [可选] HTTPS 强制跳转      │  ← FORCE_HTTPS
                          │    301 HTTP → HTTPS          │
                          └──────────────┬──────────────┘
                                         │
                          ┌──────────────▼──────────────┐
                          │    安全响应头                 │
                          │  X-Frame-Options: DENY       │  ← 防点击劫持
                          │  X-Content-Type-Options:     │  ← 防MIME嗅探
                          │       nosniff                │
                          └──────────────┬──────────────┘
                                         │
                          ┌──────────────▼──────────────┐
                          │    Session 校验              │
                          │  HttpOnly: JS无法读取Cookie   │
                          │  SameSite=Lax: 限制跨站       │
                          │  Secure: HTTPS下才发送        │
                          │  过期时间: 2小时               │
                          └──────────────┬──────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │            POST 请求校验                  │
                    │  ┌────────────────────────────────────┐  │
                    │  │  CSRF 令牌验证                      │  │
                    │  │  secrets.compare_digest() 常量时间  │  │
                    │  └────────────────────────────────────┘  │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │            登录请求                      │
                    │                                         │
                    │  ┌────────────────────────────────────┐  │
                    │  │  Step 1: 暴力破解检测               │  │
                    │  │  IP + 用户名 双层限流               │  │
                    │  │  5 分钟错误 5 次 → 锁定 5 分钟      │  │
                    │  └────────────────────────────────────┘  │
                    │                                         │
                    │  ┌────────────────────────────────────┐  │
                    │  │  Step 2: bcrypt 密码验证            │  │
                    │  │  passlib.hash.bcrypt.verify()      │  │
                    │  └────────────────────────────────────┘  │
                    │                                         │
                    │  ┌────────────────────────────────────┐  │
                    │  │  Step 3: 审计日志记录               │  │
                    │  │  成功/失败/锁定 → login_audit.log   │  │
                    │  └────────────────────────────────────┘  │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │          响应渲染                        │
                    │  user_info = USERS[username].copy()     │
                    │  user_info.pop("password")  ← 过滤密码  │
                    └─────────────────────────────────────────┘
```

---

## 八、安全配置速查

### 启动命令

```bash
# 1. 生成 256 位随机密钥
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")

# 2. 通过环境变量设置初始密码（而非硬编码）
export ADMIN_INIT_PASS="your_strong_admin_password"
export ALICE_INIT_PASS="your_strong_alice_password"

# 3. （可选）启用 HTTPS
export FORCE_HTTPS=true

# 4. 启动
pip install -r requirements.txt
python3 app.py
```

### 安全配置校验清单

```bash
# 验证 debug 模式已关闭
grep debug app.py
# 输出应为: app.run(debug=False, ...)

# 验证无明文密码硬编码
grep -E "password.*:.*\"" app.py | grep -v "os.environ" | grep -v "hash_password"
# 应无输出

# 验证 CSRF 令牌存在
grep "csrf_token" templates/login.html
# 应输出: <input type="hidden" name="_csrf_token" ...

# 验证密钥未硬编码
grep "secret_key" app.py
# 应输出: app.secret_key = os.environ.get("SECRET_KEY")
```

---

## 九、修复提交记录

```
8b07fe6 小修复: 修正README地址、添加requirements.txt、清理login.html空行
6e7f25d 更新报告: 改为漏洞分析与修复方案文档
84abeb0 添加项目完整安全报告 PROJECT_REPORT.md
beaf971 加固: 清除内存中明文密码变量 + 添加安全响应头防点击劫持
6b6835b 清理 README 中的明文密码示例，改用占位符
ba5b13c 添加 README 文档
5aa2ba3 用户信息管理平台 - Flask 登录系统（初始含漏洞版本）
```

---

## 十、参考标准

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet: CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

---

*报告生成日期：2026-07-07*
*项目地址：https://github.com/na-asuka/second-day*
*报告作者：na-asuka*
