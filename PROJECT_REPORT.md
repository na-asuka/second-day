# 用户信息管理平台 — 漏洞分析与修复报告

---

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 项目名称 | 用户信息管理平台 |
| 技术栈 | Python Flask + Jinja2 + passlib(bcrypt) |
| 仓库地址 | https://github.com/na-asuka/second-day |

本项目是一个基于 Python Flask 的用户信息管理登录系统。本文档从初始版本的代码出发，逐个分析存在的安全漏洞，描述利用场景与风险等级，并给出完整的修复方案。

---

## 二、初始版本漏洞代码

### 2.1 app.py（初始版）

```python
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"                     # [漏洞3] 弱密钥硬编码

USERS = {
    "admin": {
        "password": "admin123",                      # [漏洞1] 明文存储
        "username": "admin", "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000", "balance": 99999,
    },
    "alice": {
        "password": "alice2025",                     # [漏洞1] 明文存储
        "username": "alice", "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001", "balance": 100,
    },
}

@app.route("/")
def index():
    username = session.get("username")
    if username and username in USERS:
        user_info = USERS[username]                  # [漏洞5] 完整信息含密码
    return render_template("index.html", username=username, user=user_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username           # [漏洞1] == 明文比对
            return render_template("index.html", user=USERS[username])
        else:                                        # [漏洞6] 直接渲染无重定向
            return render_template("login.html", error="...")
    return render_template("login.html")             # [漏洞7] 无CSRF令牌
                                                      # [漏洞8] 无暴力破解防护
@app.route("/logout")                                 # [漏洞9] 无会话安全配置
def logout():                                         # [漏洞13] GET登出
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)   # [漏洞2] 调试模式RCE
```

### 2.2 templates/login.html（初始版）

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
<!-- [漏洞4] HTML注释泄露凭据 -->
{% extends "base.html" %}
{% block content %}
...
    <form method="post" action="/login">    <!-- [漏洞7] 无CSRF令牌 -->
        ...
    </form>
...
{% endblock %}
```

### 2.3 templates/index.html（初始版）

```html
...
<li><span class="label">密码：</span>{{ user.password }}</li>    <!-- [漏洞5] 密码明文显示 -->
...
<a href="/logout" class="btn btn-danger">退出登录</a>             <!-- [漏洞13] GET登出 -->
```

---

## 三、漏洞逐项分析与修复

### 🔴 漏洞一：密码明文存储与比对

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A02:2021 – 加密失败 |
| CWE 参考 | CWE-312: Cleartext Storage of Sensitive Information |
| 严重级别 | 🔴 高危 |

**风险分析：**
- 代码仓库泄露即密码泄露，攻击者直接获得所有用户原始密码
- 用户多在多平台使用相同密码，可被撞库攻击
- `==` 字符串非恒定时间比对，存在时序攻击风险

**修复方案：**

```python
from passlib.hash import bcrypt

def hash_password(plain):
    return bcrypt.hash(plain)                                    # 自动加盐

def verify_password(plain, hashed):
    try: return bcrypt.verify(plain, hashed)
    except: return False

admin_pass = os.environ.get("ADMIN_INIT_PASS")                   # 环境变量注入
USERS = {"admin": {"password": hash_password(admin_pass)}}       # 立即哈希
del admin_pass                                                   # 内存清除
```

---

### 🔴 漏洞二：调试模式开启

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A05:2021 – 安全配置错误 |
| CWE 参考 | CWE-489: Active Debug Code |
| 严重级别 | 🔴 高危 |

**风险分析：**
- Werkzeug 调试器提供交互式 Python 终端（RCE）
- 攻击者触发任意异常 → 浏览器中执行任意系统命令
- 结合 `host="0.0.0.0"`，局域网内任何攻击者都可利用

**修复方案：** `debug=True` → `debug=False`

---

### 🔴 漏洞三：弱密钥硬编码

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A02:2021 – 加密失败 |
| CWE 参考 | CWE-321: Use of Hard-coded Cryptographic Key |
| 严重级别 | 🔴 高危 |

**风险分析：**
- 弱密钥可被暴力破解，攻击者可伪造任意用户 session cookie
- 密钥存在于代码仓库中，所有能访问仓库的人都能获取

**修复方案：**

```python
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("环境变量 SECRET_KEY 未设置")
```

---

### 🔴 漏洞四：HTML 注释泄露管理员凭据

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A01:2021 – 访问控制失效 |
| CWE 参考 | CWE-200: Exposure of Sensitive Information |
| 严重级别 | 🔴 高危 |

**漏洞位置：** `templates/login.html`

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

**风险分析：** 页面源码中完全可见，查看源代码即可直接获取管理员账号密码。

**修复方案：** 删除该注释行。

---

### 🟡 漏洞五：页面明文显示密码

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A04:2021 – 不安全设计 |
| 严重级别 | 🟡 中危 |

**漏洞位置：** `templates/index.html`

```html
<li><span class="label">密码：</span>{{ user.password }}</li>
```

**风险分析：** 肩窥攻击、屏幕共享、截图等场景下直接泄露密码。

**修复方案：**

后端过滤：
```python
user_info = {k: v for k, v in USERS[username].items() if k != "password"}
```

前端移除密码行。

---

### 🟡 漏洞六：登录后直接渲染模板

| 属性 | 内容 |
|------|------|
| 严重级别 | 🟡 中危 |

**风险分析：** POST 成功后直接 `render_template()`，用户刷新页面时浏览器弹出"确认重新提交表单"对话框，不符合 Post/Redirect/Get（PRG）设计模式。

**修复方案：** `render_template(...)` → `redirect(url_for("index"))`

---

### 🟡 漏洞七：无 CSRF 防护

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A01:2021 – 访问控制失效 |
| CWE 参考 | CWE-352: Cross-Site Request Forgery |
| 严重级别 | 🟡 中危 |

**风险分析：** 登录表单无 CSRF 令牌，攻击者可构造恶意页面跨站提交表单。

**修复方案：**

```python
@app.context_processor
def _inject_csrf_token():
    session.setdefault("_csrf_token", secrets.token_hex(32))
    return {"csrf_token": session["_csrf_token"]}

def _csrf_validate():
    token = request.form.get("_csrf_token")
    return bool(token and secrets.compare_digest(token, session.get("_csrf_token", "")))
```

---

### 🟡 漏洞八：无暴力破解防护

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A07:2021 – 身份验证失效 |
| 严重级别 | 🟡 中危 |

**风险分析：** 登录接口无频率限制，攻击者可无限尝试密码字典。

**修复方案：** IP + 用户名双层限流，5 分钟内失败 5 次则锁定 5 分钟。

---

### 🟡 漏洞九：无会话安全配置

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A07:2021 – 身份验证失效 |
| 严重级别 | 🟡 中危 |

**风险分析：** Cookie 缺少 HttpOnly、SameSite、过期时间等安全配置。

**修复方案：**

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True if os.environ.get("FORCE_HTTPS") else False,
)
app.permanent_session_lifetime = timedelta(hours=2)
```

---

### 🟢 漏洞十：无安全响应头

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A05:2021 – 安全配置错误 |
| 严重级别 | 🟢 低危 |

**风险分析：** 页面可被嵌入 iframe（点击劫持），浏览器可能 MIME 嗅探。

**修复方案：**

```python
@app.after_request
def _set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

---

### 🟡 漏洞十一：登出接口为 GET 请求

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A07:2021 – 身份验证失效 |
| CWE 参考 | CWE-306: Missing Authentication for Critical Function |
| 严重级别 | 🟡 中危 |

**风险分析：** 攻击者可嵌入 `<img src="http://target/logout">` 强制登出用户。

**修复方案：**

```python
@app.route("/logout", methods=["POST"])
def logout():
    ...
```

前端改为 POST 表单提交，携带 CSRF 令牌。

---

### 🟢 漏洞十二：无审计日志

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A09:2021 – 安全日志与监控失效 |
| 严重级别 | 🟢 低危 |

**风险分析：** 攻击事件无法追溯。

**修复方案：** RotatingFileHandler（5MB 轮转，保留 3 份），记录登录成功/失败/锁定/登出事件。

---

### 🟢 漏洞十三：无 HTTPS 支持

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A02:2021 – 加密失败 |
| 严重级别 | 🟢 低危 |

**风险分析：** 数据明文传输，中间人可窃听密码和 session cookie。

**修复方案：** 设置 `FORCE_HTTPS` 环境变量后自动 301 跳转 HTTPS。

---

### 🟢 漏洞十四：暴力破解未适配反向代理

| 属性 | 内容 |
|------|------|
| OWASP 分类 | A05:2021 – 安全配置错误 |
| 严重级别 | 🟢 低危 |

**风险分析：** 部署在 Nginx 后时 `request.remote_addr` 始终为反向代理 IP，限流失效。

**修复方案：**

```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
```

---

## 四、漏洞修复对照表

| 编号 | 漏洞名称 | 初始状态 | 修复方式 | 级别 |
|:----:|----------|----------|----------|:----:|
| 01 | 密码明文存储与比对 | `"admin123"` 明文 + `==` 比对 | bcrypt 哈希 + 环境变量注入 | 🔴 |
| 02 | 调试模式 RCE | `debug=True` | 关闭调试模式 | 🔴 |
| 03 | 弱密钥硬编码 | `"dev-key-2025"` | 环境变量强制注入 | 🔴 |
| 04 | HTML 注释泄露凭据 | `<!-- 密码: admin123 -->` | 删除注释行 | 🔴 |
| 05 | 页面明文显示密码 | `{{ user.password }}` | 后端过滤 + 前端移除 | 🟡 |
| 06 | 登录直接渲染模板 | `render_template()` | `redirect(url_for("index"))` | 🟡 |
| 07 | 无 CSRF 防护 | 表单无令牌 | `token_hex(32)` + `compare_digest()` | 🟡 |
| 08 | 无暴力破解防护 | 无限制 | IP+用户名 5次/5分钟限流 | 🟡 |
| 09 | 无会话安全配置 | 无 | HttpOnly + SameSite + 2h 过期 | 🟡 |
| 10 | 无安全响应头 | 无 | X-Frame-Options + CSP + nosniff | 🟢 |
| 11 | 登出为 GET | `<a href="/logout">` | POST 表单 + CSRF 令牌 | 🟡 |
| 12 | 无审计日志 | 无 | RotatingFileHandler 日志轮转 | 🟢 |
| 13 | 无 HTTPS 支持 | 仅 HTTP | FORCE_HTTPS 可选跳转 | 🟢 |
| 14 | 无反向代理适配 | remote_addr 直取 | ProxyFix 中间件 | 🟢 |

---

## 五、修复后完整代码

### 5.1 app.py（最终版）

```python
import os, re, secrets, logging
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

def hash_password(plain):
    return bcrypt.hash(plain)

def verify_password(plain, hashed):
    try: return bcrypt.verify(plain, hashed)
    except: return False

admin_pass = os.environ.get("ADMIN_INIT_PASS")
if not admin_pass: raise RuntimeError("ADMIN_INIT_PASS 未设置")
alice_pass = os.environ.get("ALICE_INIT_PASS")
if not alice_pass: raise RuntimeError("ALICE_INIT_PASS 未设置")

USERS = {
    "admin": {"username": "admin", "password": hash_password(admin_pass),
              "role": "admin", "email": "admin@example.com",
              "phone": "13800138000", "balance": 99999},
    "alice": {"username": "alice", "password": hash_password(alice_pass),
              "role": "user", "email": "alice@example.com",
              "phone": "13900139001", "balance": 100},
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

@app.route("/")
def index():
    username = session.get("username")
    if username in USERS:
        user_info = USERS[username].copy(); user_info.pop("password")
    else: user_info = None
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
        user = USERS.get(username)
        if user and verify_password(password, user["password"]):
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

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
```

### 5.2 templates/base.html（最终版）

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户管理系统</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-left"><span class="brand">用户管理系统</span></div>
        <div class="nav-right">
            {% if session.get("username") %}
                <span class="nav-welcome">欢迎，{{ session["username"] }}</span>
                <form method="post" action="/logout" class="nav-form">
                    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                    <button type="submit" class="nav-link-btn">退出</button>
                </form>
            {% else %}
                <a href="/login" class="nav-link">登录</a>
            {% endif %}
        </div>
    </nav>
    <main class="container">{% block content %}{% endblock %}</main>
</body>
</html>
```

### 5.3 templates/login.html（最终版）

```html
{% extends "base.html" %}
{% block content %}
<div class="card card-login">
    <h2>用户登录</h2>
    <hr>
    {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
    <form method="post" action="/login">
        <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
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

### 5.4 templates/index.html（最终版）

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
        <form method="post" action="/logout">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
            <button type="submit" class="btn btn-danger">退出登录</button>
        </form>
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
| 数据泄露 → 密码泄露 | 明文密码直接暴露 | bcrypt 不可逆哈希 |
| 远程代码执行 RCE | debug=True 可执行任意代码 | 已禁用 |
| 会话伪造 | 弱密钥可猜测 | 256 位随机密钥 |
| 信息泄露 → 页面源码 | HTML 注释暴露凭据 | 已删除 |
| 信息泄露 → 肩窥 | 密码明文显示在页面 | 已过滤 |
| 表单重复提交 | 刷新弹窗"确认重新提交" | PRG 重定向模式 |
| 跨站请求伪造 CSRF | 无令牌保护 | 256 位令牌 + 常量时间比对 |
| CSRF 强制登出 | GET 链接即可登出 | POST 表单 + CSRF 令牌 |
| 暴力破解 | 无限制无限尝试 | IP+用户名 5次/5分钟锁定 |
| 会话劫持 | 无 HttpOnly/SameSite | HttpOnly + SameSite + 2h 过期 |
| 点击劫持 | 可嵌入 iframe | X-Frame-Options: DENY |
| MIME 嗅探 | 无保护 | X-Content-Type-Options: nosniff |
| XSS / 资源注入 | 无保护 | CSP: default-src 'self' |
| 反向代理 IP 欺骗 | remote_addr 始终为代理 IP | ProxyFix 提取真实 IP |
| 中间人攻击 | 纯 HTTP 明文传输 | HTTPS 可选强制跳转 |
| 安全审计 | 无日志记录 | 完整日志 + 文件轮转 |

---

## 七、安全架构全景

```
用户请求
   │
   ├─ [可选] HTTPS 301 跳转 (FORCE_HTTPS)
   │
   ├─ 安全响应头
   │   ├─ X-Frame-Options: DENY           ← 防点击劫持
   │   ├─ X-Content-Type-Options: nosniff  ← 防MIME嗅探
   │   └─ Content-Security-Policy          ← 防XSS/资源注入
   │
   ├─ Session 校验
   │   ├─ HttpOnly ──── JS 无法读取 Cookie
   │   ├─ SameSite=Lax ── 限制跨站发送
   │   └─ 2 小时自动过期
   │
   ├─ POST 请求 → CSRF 令牌验证 (secrets.compare_digest)
   │
   ├─ 登录流程
   │   ├─ 暴力破解检测 (IP+用户名, 5次/5分钟)
   │   ├─ bcrypt 密码验证
   │   └─ 审计日志记录 (成功/失败/锁定/登出)
   │
   └─ 响应渲染 → 密码字段过滤 (pop("password"))
```

---

## 八、启动与校验

### 启动命令

```bash
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
export ADMIN_INIT_PASS="your_strong_password"
export ALICE_INIT_PASS="your_strong_password"
pip install -r requirements.txt
python3 app.py
```

访问 **http://127.0.0.1:5000**

### 安全配置校验

```bash
grep debug app.py                    # 应为 debug=False
grep "secret_key" app.py | grep -v "#"  # 应为 os.environ.get
grep csrf_token templates/login.html   # 应有 hidden input
grep -E "password.*:.*\"[a-z]" app.py | grep -v hash  # 应无输出
```

---

## 九、修复提交记录

```
fc618c3 README: 更新为pip install -r requirements.txt
f75ba46 修复: CSP兼容性-移除内联style/添加按钮样式
0cd2d19 修复: 登出改为POST+ProxyFix+CSP安全头+报告同步更新
af73b6e 完善漏洞报告: OWASP分类/初始代码全本/攻击场景
8b07fe6 小修复: 修正README地址/requirements.txt/空行清理
beaf971 加固: 内存清除明文密码 + 安全响应头
6b6835b 清理 README 明文密码
ba5b13c 添加 README 文档
5aa2ba3 初始含漏洞版本
```

---

## 十、参考标准

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-321: Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

---

*报告生成日期：2026-07-07*
*项目地址：https://github.com/na-asuka/second-day*
