# SQL注入漏洞 — 类型分析与修复方案报告

---

## 一、实验信息

| 项目 | 内容 |
|------|------|
| 实验日期 | 2026-07-08 |
| 本机访问地址 | `http://127.0.0.1:5000` |
| 局域网访问地址 | `http://192.168.164.128:5000` |
| 测试账号1 | admin / admin123（管理员） |
| 测试账号2 | alice / alice2025（普通用户） |
| 技术栈 | Python 3.13 + Flask 3.x + SQLite 3 + passlib(bcrypt) |
| 数据库 | `data/users.db` |

---

## 二、完整源码（app.py）

```python
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

@app.route("/logout", methods=["POST"])
def logout():
    logger.info("登出: %s",session.get("username"));session.clear();return redirect(url_for("index"))

def _lk(u): return f"{request.remote_addr}:{u}"
def _is_lk(u): n=time();k=_lk(u);a=[t for t in LOGIN_AT.get(k,[]) if n-t<LOCK_MIN*60];LOGIN_AT[k]=a;return len(a)>=MAX_AT
def _rf(u): LOGIN_AT.setdefault(_lk(u),[]).append(time())
def _cl(u): LOGIN_AT.pop(_lk(u),None)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
```

---

## 三、SQL注入攻击链（9步）

```
第一步：判断是否存在注入点
  搜索框输入:  '           → 如果页面返回错误(如SQL语法错误)
  或输入:      ' OR '1'='1 → 如果返回全部数据 → 存在注入

第二步：判断注入点类型
  本项目搜索框使用 LIKE 进行字符串模糊匹配，属于字符型注入。
  验证方式：输入 ' 触发语法错误 → 确认存在字符型注入点。
  闭合方式探测：尝试 '、"、') 等，观察报错信息确定闭合符为 '。

第三步：判断闭合方式
  本例闭合方式：'（单引号）

第四步：判断列数
  ' ORDER BY 4 --  → 正常返回
  ' ORDER BY 5 --  → 报错 → 列数为 4（若5报错4正常）
  或使用 UNION SELECT NULL 逐次探测：
  ' UNION SELECT NULL --
  ' UNION SELECT NULL,NULL --
  ' UNION SELECT NULL,NULL,NULL --
  ' UNION SELECT NULL,NULL,NULL,NULL --   → 正常（4列）
  ' UNION SELECT NULL,NULL,NULL,NULL,NULL -- → 报错（超列数）

第五步：查询回显位置
  ' UNION SELECT 1,2,3,4 --
  页面显示的数字即为回显位置。本例回显位置为 2,3,4。

第六步：获取数据库名
  ' UNION SELECT 1,2,database(),4 --

第七步：获取表名（SQLite语法）
  ' UNION SELECT 1,2,group_concat(name),4 FROM sqlite_master WHERE type='table' --

第八步：获取列名
  ' UNION SELECT 1,2,group_concat(name),4 FROM pragma_table_info('users') --

第九步：获取数据
  ' UNION SELECT 1,2,password,4 FROM users --
```

---

## 三、SQL注入类型详解

### 类型①：UNION注入

**原理：** 利用 `UNION SELECT` 合并攻击者构造的查询结果。

**攻击场景：**
```
搜索框:  ' UNION SELECT 1,'inj','inj@x.com','138' --
效果:    搜索结果中出现 "inj" 用户名
```

**为何需要4列？**
```sql
-- 原查询返回4列 (id, username, email, phone)
SELECT id, username, email, phone FROM users WHERE ...
-- UNION SELECT 也必须返回4列
UNION SELECT 1, 'inj', 'inj@x.com', '138'
-- 列数不匹配会报错
```

**修复方案：**
```python
# ❌ 漏洞写法（f-string 拼接 — 本项目中已不存在）
sql = f"SELECT ... WHERE username LIKE '%{keyword}%'"

# ✅ 安全写法（参数化查询）
sql = "SELECT ... WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))
```

---

### 类型②：OR注入

**原理：** 利用 `OR '1'='1'` 构造永真条件。

**攻击场景：**
```
搜索框:  ' OR '1'='1
SQL:     SELECT ... WHERE username LIKE '%' OR '1'='1%'
效果:    返回数据库中所有用户
```

**在安全版中：** 参数化查询将 `' OR '1'='1` 当作普通文本值传入 LIKE 匹配，不会触发永真条件，返回"无搜索结果"。

---

### 类型③：AND布尔盲注

**原理：** 利用 `AND` 构造条件判断，根据页面是否返回数据推断数据库信息。
注意：必须使用 `--` 注释符闭合尾部 SQL，否则尾部 `%'` 会导致条件失效。

**攻击场景：**
```
条件为真:  admin' AND '1'='1' --   → 返回数据
条件为假:  admin' AND '1'='2' --   → 无数据
```

**猜解过程（以数据库名为例）：**
```
搜索:  admin' AND length(database())=4 --  → 有数据 → 库名长度=4
搜索:  admin' AND substr(database(),1,1)='m' --  → 有数据 → 首字母'm'
搜索:  admin' AND substr(database(),2,1)='a' --  → 有数据 → 第二字母'a'
...逐个猜解直至完整 → "main"
```

---

### 类型④：LIKE通配符注入

**原理：** LIKE 支持 `%`（匹配任意多字符）和 `_`（匹配单个字符）通配符。

**攻击场景：**
```
%       → 返回全部用户（当keyword=%，LIKE '%%'匹配所有行）
%a%     → 返回所有包含字母a的用户
admin_  → 返回admin开头+1个字符的用户
```

**修复方案：** 如需防止通配符，可转义：
```python
keyword = keyword.replace("%", "\\%").replace("_", "\\_")
```

---

### 类型⑤：INSERT注入

**原理：** 在注册表单字段中插入 SQL 代码，闭合 INSERT 语句。

**攻击场景：**
```
用户名:   hacker', 'hack123', 'h@x.com', '999') --
密码:     irrelevant (被注释掉)
效果:     ) -- 注释掉后续SQL，插入伪造数据
```

**修复方案（本项目的做法）：**
```python
# 参数化查询，用户输入只作为参数值传入
sql = "INSERT INTO users VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

---

## 四、攻击URL解码对照

```bash
# 以下为POC中URL编码的攻击Payload的解码对照

# OR注入
编码: %27%20OR%20%271%27%3D%271
解码: ' OR '1'='1
说明: 单引号闭合LIKE → OR永真条件 → 返回全部用户

# UNION注入（插入假数据）
编码: %27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--
解码: ' UNION SELECT 1,'inj','inj@x.com','138'--
说明: 闭合后UNION SELECT插入4列伪造数据

# AND布尔盲注（条件为真）
编码: admin%27%20AND%20%271%27%3D%271%27%20--
解码: admin' AND '1'='1' --
说明: AND条件为真，页面返回数据

# AND布尔盲注（条件为假）
编码: admin%27%20AND%20%271%27%3D%272%27%20--
解码: admin' AND '1'='2' --
说明: AND条件为假，页面无数据
```

---

## 五、后台执行日志

实验过程中 Flask 后台输出的请求日志（`login_audit.log`）：

```
INFO:auth:登录: admin
INFO:werkzeug:POST /login HTTP/1.1" 302 -
INFO:werkzeug:GET / HTTP/1.1" 200 -

# 正常搜索 admin
INFO:werkzeug:GET /search?keyword=admin HTTP/1.1" 200 -

# OR注入请求（参数全程URL编码传输）
INFO:werkzeug:GET /search?keyword='%20OR%20'1'%3D'1 HTTP/1.1" 200 -
# 后台执行SQL: SELECT id,username,email,phone FROM users WHERE username LIKE ? OR email LIKE ?
# 参数: ('%\' OR \'1\'=\'1%', '%\' OR \'1\'=\'1%')
# 结果: 无搜索结果（注入被参数化查询拦截 ✅）

# UNION注入请求
INFO:werkzeug:GET /search?keyword='%20UNION%20SELECT%201,'inj','inj@x.com','138'-- HTTP/1.1" 200 -
# 后台执行SQL: SELECT id,username,email,phone FROM users WHERE username LIKE ? OR email LIKE ?
# 参数: ('%\' UNION SELECT 1,\'inj\',\'inj@x.com\',\'138\'--%', ...)
# 结果: 无搜索结果（注入了整段文字作为普通搜索关键词 ✅）

# 新用户注册
INFO:werkzeug:POST /register HTTP/1.1" 200 -
# 后台执行SQL: INSERT INTO users (username,password,email,phone,role,balance) VALUES (?,?,?,?,'user',0)
# 参数: ('testuser', '<bcrypt_hash>', 't@t.com', '13800138000')
# bcrypt哈希后入库 ✅
```

---

## 六、修复前后SQL对比

### 搜索功能

| 操作 | 漏洞写法（f-string拼接） | 安全写法（参数化查询） |
|------|-------------------------|----------------------|
| 搜索admin | `f"SELECT ... WHERE username LIKE '%admin%'"` | `SELECT ... WHERE username LIKE ?` + 参数`('%admin%',)` |
| OR注入 | `f"SELECT ... WHERE username LIKE '%' OR '1'='1%'"` | `SELECT ... WHERE username LIKE ?` + 参数`('%\' OR \'1\'=\'1%',)` |
| UNION注入 | `f"SELECT ... WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'"` | `SELECT ... WHERE username LIKE ?` + 参数`('%\' UNION SELECT...%',)` |
| 用户输入角色 | **当作SQL代码执行** → 注入成功 | **当作普通文本匹配** → 注入失败 |

### 注册功能

| 操作 | 漏洞写法（f-string拼接） | 安全写法（参数化查询） |
|------|-------------------------|----------------------|
| 正常注册 | `f"INSERT INTO users VALUES ('alice','pass123',...)"` | `INSERT INTO users VALUES (?,?,?,?)` + 参数 |
| INSERT注入 | `f"INSERT INTO users VALUES ('hacker', 'hack123',... )--', ...)"` | `INSERT INTO users VALUES (?,?,?,?)` + 参数 → 注入字符被转义为普通数据 |
| 密码存储 | 明文 `'pass123'` | `hash_pw(p)` → bcrypt哈希后入库 |

### 关键区别图解

```
漏洞版（f-string）:
  用户输入: ' OR '1'='1
  SQL:      SELECT ... WHERE username LIKE '%' OR '1'='1%'
                                    ↑↑↑↑↑↑↑↑↑↑↑↑
                            用户输入成为SQL语法的一部分 → 注入成功

安全版（参数化查询）:
  用户输入: ' OR '1'='1
  SQL:      SELECT ... WHERE username LIKE ?  ← 预编译，?是占位符
  参数:     ('%' OR '1'='1%')
             ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
            用户输入被整体当作字符串值传入 → 仅做LIKE文本匹配 → 注入失败
```

---

## 七、代码对比（漏洞版 vs 安全版）

### 搜索功能

| 维度 | 漏洞写法（演示用） | 安全写法（本项目） |
|------|-------------------|-------------------|
| SQL构建 | `f"...LIKE '%{keyword}%'"` | `"...LIKE ?"` |
| 用户输入 | 拼接为SQL代码 | 作为参数传入 |
| `' OR '1'='1` | 变为永真条件 | 当作普通文本 |
| `' UNION SELECT...` | 合并到结果 | 当作普通文本 |
| 数据库执行 | `c.execute(sql)` | `c.execute(sql, params)` |

### 注册功能

| 维度 | 漏洞写法 | 安全写法 |
|------|---------|---------|
| SQL构建 | `f"VALUES ('{username}')"` | `"VALUES (?)"` |
| 闭合注入 | `hacker')--` 可闭合 | 参数化无法闭合 |
| 密码存储 | 明文 | bcrypt 哈希 |

---

## 八、POC 测试命令

```bash
# 登录获取 session
CSRF=$(curl -s -c /tmp/c.txt http://localhost:5000/login | grep -oP 'name="_csrf_token" value="\K[^"]+')
curl -s -b /tmp/c.txt -c /tmp/c.txt \
  -d "username=admin&password=admin123&_csrf_token=$CSRF" \
  http://localhost:5000/login -L -o /dev/null

# 由于本项目采用参数化查询，以下注入全部被拦截
# 仅作为攻击原理演示，实际不会返回数据

# POC 1：UNION 注入（攻击原理）
curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"
# 预期结果：无搜索结果（注入被拦截）

# POC 2：OR 注入（攻击原理）
curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"
# 预期结果：无搜索结果（注入被拦截）
```

---

## 九、防御方案对比

| 防御措施 | 效果 | 实现成本 | 推荐度 |
|----------|------|----------|:------:|
| **参数化查询 `?`** | 彻底杜绝注入 | 低 | ⭐⭐⭐⭐⭐ |
| 输入过滤/转义 | 可能被绕过 | 中 | ⭐⭐⭐ |
| WAF | 可被绕过 | 高 | ⭐⭐ |
| ORM框架 | 内置防护 | 低 | ⭐⭐⭐⭐⭐ |
| 最小权限原则 | 减少损失 | 低 | ⭐⭐⭐⭐ |

---

## 十、修复铁律

```
┌──────────────────────────────────────────┐
│              SQL注入防御铁律              │
│                                          │
│  ❌ 永远不要用 f-string 拼接 SQL         │
│  ❌ 永远不要相信用户输入                  │
│  ✅ 始终使用参数化查询 ? 占位符          │
│  ✅ 最小权限原则（不用 root 连库）       │
│  ✅ 错误信息不暴露给用户                  │
└──────────────────────────────────────────┘
```

---

*报告生成日期：2026-07-08*
*项目地址：https://github.com/na-asuka/second-day*
