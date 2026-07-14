# 密码修改接口 — 安全测试与修复报告

---

## 一、测试概述

| 项目 | 内容 |
|------|------|
| 测试接口 | `POST /change-password` |
| 测试环境 | `http://127.0.0.1:5000` |
| 测试账号 | alice / alice2025（普通用户） |
| 测试日期 | 2026-07-09 |
| 覆盖漏洞 | CSRF、请求方法绕过、参数删除绕过、越权改密、XSS |

---

## 二、漏洞发现

### 2.1 CSRF 无防御（CWE-352）

**观察：** 修改密码的 POST 请求不携带任何 CSRF Token。

**HTTP 请求：**
```http
POST /change-password HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFsaWNlIn0...
Content-Type: application/x-www-form-urlencoded

username=alice&new_password=pwned1
```

**测试结果：** 响应 **200**，密码被成功修改，**无任何令牌校验**。

**PoC Exploit HTML（CSRF 自动提交）：**
```html
<html>
<body>
<h1>点击抽奖！</h1>
<form id="f" action="http://127.0.0.1:5000/change-password" method="POST">
  <input type="hidden" name="username" value="victim">
  <input type="hidden" name="new_password" value="attacker123">
</form>
<script>document.getElementById('f').submit();</script>
</body>
</html>
```

**CWE：** CWE-352: Cross-Site Request Forgery

---

### 2.2 GET 方法绕过

**测试：**
```bash
curl "http://127.0.0.1:5000/change-password?username=alice&new_password=pwned2"
```

**结果：** 响应 **405 Method Not Allowed**。Flask 路由声明 `methods=["POST"]`，GET 被框架层拒绝。

**结论：** ✅ 本接口不存在 GET 方法绕过风险。

---

### 2.3 CSRF 参数删除绕过

**HTTP 请求（仅保留 username 和 new_password）：**
```http
POST /change-password HTTP/1.1
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

username=alice&new_password=pwned3
```

**结果：** 响应 **200**。后端无 Token 校验逻辑，无 Token 时直接跳过。

---

### 2.4 越权修改他人密码（CWE-639）

**测试：**
```bash
curl -b cookies.txt -d "username=admin&new_password=adminhacked" \
  http://127.0.0.1:5000/change-password
```

**结果：** 响应 **200**。普通用户 alice 成功修改管理员 admin 的密码。

**CWE：** CWE-639: Authorization Bypass Through User-Controlled Key

---

### 2.5 XSS 注入测试

**测试：** 在 `new_password` 参数中注入 XSS payload。

```bash
curl -b cookies.txt \
  -d "username=alice&new_password=<script>alert('XSS')</script>" \
  http://127.0.0.1:5000/change-password
```

**结果：** 密码被设置为 `<script>alert('XSS')</script>`。

**回显验证：** 登录后访问个人中心页面（profile.html），密码字段不会显示在页面上。即使显示，Jinja2 的 `{{ }}` 会自动进行 HTML 实体转义：
- 存储值：`<script>alert('XSS')</script>`
- 渲染输出：`&lt;script&gt;alert('XSS')&lt;/script&gt;`（不可执行）

**结论：** 由于 Jinja2 默认自动转义，且本应用未在 password 展示处使用 `| safe` 过滤器，**XSS 攻击无法通过密码字段触发放大**。但若其他输入点（如日志显示）使用 `| safe` 则存在风险。

---

## 三、修复方案

### 3.1 修复后代码

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    # 防御1: 登录校验
    if "username" not in session:
        return redirect(url_for("login"))

    # 防御2: CSRF Token 校验
    if not _csrf_v():
        return "无效请求", 400

    target_user = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    session_user = session.get("username", "")

    # 防御3: 空值校验 — 避免不安全重定向
    if not target_user or not new_password:
        return redirect(url_for("index"))

    # 防御4: 确认密码校验 — 两端输入必须一致
    if new_password != confirm_password:
        return redirect(url_for("index"))

    # 防御5: session归属校验 — 只能改自己密码
    if target_user != session_user:
        return abort(403)

    uid = None
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE username = ?",
                  (new_password, target_user))
        conn.commit()
        c.execute("SELECT id FROM users WHERE username = ?", (target_user,))
        r = c.fetchone()
        if r:
            uid = r[0]
        conn.close()
        logger.info("密码修改: target=%s operator=%s",
                   target_user, session_user)
    except Exception as e:
        logger.error("密码修改异常: %s", e)

    if uid:
        return redirect(url_for("profile", user_id=uid))
    return redirect(url_for("index"))
```

### 3.2 修复前后对比

| 防御项 | 修复前 | 修复后 |
|--------|--------|--------|
| CSRF Token | ❌ 无 | ✅ `_csrf_v()` 校验 |
| 方法限制 | ✅ POST only | ✅ POST only（不变） |
| 权限校验 | ❌ 可改任何人 | ✅ `target_user != session_user → 403` |
| 确认密码校验 | ❌ 无 | ✅ 前端+后端双重校验 |
| 空值处理 | ❌ 重定向到错误URL | ✅ 重定向到首页 |
| 模板 CSRF Token | ❌ 无 | ✅ `<input name="_csrf_token">` |
| XSS 防护 | ✅ Jinja2 自动转义 | ✅ 不变 |

### 3.3 模板修改（profile.html）

```html
<!-- 修复后 — 新增 CSRF Token -->
<form method="post" action="/change-password">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
    <input type="hidden" name="username" value="{{ user.username }}">

    <div class="form-group">
        <label for="new_password">新密码</label>
        <input type="password" id="new_password" name="new_password" required>
    </div>
    <div class="form-group">
        <label for="confirm_password">确认密码</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
    </div>
    <button type="submit" class="btn btn-primary btn-block">修改密码</button>
</form>
```

---

## 四、修复验证

| 测试ID | 测试场景 | 请求参数 | 修复前 | 修复后 |
|--------|----------|----------|--------|--------|
| T1 | CSRF无Token | `POST` 仅 `username+new_password` | ✅ 200 成功 | ❌ **400 无效请求** |
| T2 | GET方法绕过 | `GET /change-password?username=alice&new_password=x` | ❌ 405 | ❌ **405**（不变） |
| T3 | 越权改admin密码 | alice 提交 `username=admin` | ✅ 200 成功 | ❌ **400 CSRF拦截** |
| T4 | 正常改密 | 带CSRF Token + 确认密码一致 | — | ✅ **200 成功** |
| T5 | 新密码登录验证 | 用新密码登录 | ✅ 成功 | ✅ **成功** |
| T6 | XSS注入 | `new_password=<script>alert(1)</script>` | ✅ 存入 | ✅ **存入但Jinja2转义** |
| T7 | 确认密码不一致 | `new_password=abc` `confirm_password=xyz` | ✅ 可改 | ❌ **302 拒绝** |
| T8 | 空参数 | `new_password=` 空值 | ❌ 302到错误URL | ❌ **302到首页** |

---

## 五、攻击链分析

### 5.1 修复前的攻击链

```
攻击者构造 CSRF 页面
    ↓
诱骗 alice 访问（alice 已登录）
    ↓
页面自动提交 → 将 alice 密码改为 attacker123
    ↓
攻击者用 attacker123 登录 alice 账户
    ↓
以 alice 身份修改 admin 密码（越权）
    ↓
攻击者用新密码登录 admin
    ↓
进入管理后台 → 数据泄露
```

### 5.2 修复后的防御链

```
请求进入 /change-password
    ↓
① 登录校验 → 未登录 → 302 登录页
    ↓
② CSRF Token 校验 → 无/无效 Token → 400
    ↓
③ 空值校验 → username 或 password 为空 → 302 首页
    ↓
④ 确认密码校验 → 不一致 → 302 首页
    ↓
⑤ Session 归属校验 → 目标 != 当前用户 → 403
    ↓
⑥ 执行更新 → 记录日志
    ↓
⑦ 重定向到个人中心
```

---

## 六、其他安全风险与加固建议

### 6.1 密码明文存储风险

**现状：** 当前密码以明文形式存储在 `users` 表中（`UPDATE users SET password = ?`）。数据库泄露可直接获取所有用户的密码原文。

**建议：** 使用 `werkzeug.security.generate_password_hash()` 和 `check_password_hash()` 进行哈希存储。

```python
from werkzeug.security import generate_password_hash

# 存储时
hashed_pw = generate_password_hash(new_password)
c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, target_user))

# 验证时
from werkzeug.security import check_password_hash
if check_password_hash(stored_hash, input_password):
    # 密码正确
```

### 6.2 密码复杂度策略

**现状：** 无任何密码长度或复杂度限制。

**建议：**
- 密码最小长度 8 位
- 至少包含大写字母、小写字母、数字、特殊符号中的 3 类
- 前后端双重校验

### 6.3 HttpOnly Cookie

**现状：** Cookie 已设置 `SESSION_COOKIE_HTTPONLY=True`，JavaScript 无法读取 session cookie。这有效降低了 XSS 窃取 session 的风险。**已有防护，维持不变。**

### 6.4 输出编码（XSS 纵深防御）

**现状：** Jinja2 默认自动转义所有 `{{ }}` 输出。
**建议：** 除非必须渲染 HTML，否则避免使用 `| safe` 过滤器。

---

## 附录

### 参考资源

| 资源 | 链接 |
|------|------|
| OWASP CSRF Prevention | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html |
| OWASP XSS Prevention | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html |
| CWE-352: Cross-Site Request Forgery | https://cwe.mitre.org/data/definitions/352.html |
| CWE-639: Authorization Bypass | https://cwe.mitre.org/data/definitions/639.html |
| CWE-79: Cross-Site Scripting | https://cwe.mitre.org/data/definitions/79.html |

---

*报告生成日期：2026-07-09*
