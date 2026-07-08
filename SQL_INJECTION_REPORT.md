# SQL注入漏洞 — 类型分析与修复方案报告

---

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 漏洞版端口 | 5000 — `app.py` |
| 安全版端口 | 5001 — `app_fixed.py` |
| 数据库 | SQLite 3.x |
| 漏洞版本SQL方式 | f-string 拼接 (`f"SELECT ... '{keyword}'"`) |
| 安全版本SQL方式 | 参数化查询 (`?` 占位符) |
| 数据库表字段 | id, username, password, email, phone, **role**, **balance** |
| 安全版密码存储 | bcrypt 哈希 |
| 注入类型数量 | 7 种（UNION / OR / AND布尔 / 报错 / LIKE / 堆叠 / INSERT） |

---

## 二、SQL注入类型与演示

### 类型①：UNION注入

**原理：** 利用 `UNION` 关键字将攻击者构造的查询结果合并到原始查询结果中。

**漏洞代码：**
```python
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%'"
```

**攻击Payload：**
```
搜索框输入: ' UNION SELECT 1,'黑客','hack@x.com','666'--
生成SQL:    SELECT id,username,email,phone FROM users WHERE username LIKE '%' UNION SELECT 1,'黑客','hack@x.com','666'--%'
```

**攻击效果：** 搜索结果中出现攻击者伪造的数据行。

**修复方案：**
```python
# ✅ 参数化查询
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))
```

---

### 类型②：OR注入

**原理：** 利用 `OR` 关键字构造永真条件，绕过 WHERE 过滤返回全部数据。

**漏洞代码：**
```python
sql = f"SELECT ... WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**攻击Payload：**
```
搜索框输入: ' OR '1'='1
生成SQL:    SELECT ... WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

**攻击效果：** 返回数据库中所有用户数据，泄露全部用户信息。

**修复方案：**
```python
# ✅ 用户输入作为纯数据传入，不参与SQL语法解析
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

---

### 类型③：AND布尔盲注

**原理：** 利用 `AND` 构造条件判断，根据页面是否返回数据来推断数据库信息（逐个字符猜解）。

**布尔盲注过程：**
```
# 判断数据库名长度
1' AND length(database())=8 --+    → 返回数据（真）→ 数据库名长度为8

# 逐字符猜解数据库名
1' AND substr(database(),1,1)='s'  → 返回数据（真）→ 第1个字符为's'
1' AND substr(database(),2,1)='e'  → 返回数据（真）→ 第2个字符为'e'
... → 最终得到 "security"
```

**注入类型对比：**

| Payload | 条件 | 页面表现 | 含义 |
|---------|------|----------|------|
| `admin' AND '1'='1` | 永真 | ✅ 返回数据 | 注入成功 |
| `admin' AND '1'='2` | 永假 | ❌ 无数据 | 注入可识别 |
| `admin' AND length(database())=8` | 真 | ✅ 返回数据 | 数据库名长度=8 |
| `admin' AND length(database())=7` | 假 | ❌ 无数据 | 数据库名长度≠7 |

**修复方案：** 参数化查询使 `AND`、`OR` 等关键字失去SQL语法意义。

---

### 类型④：报错注入

**原理：** 利用数据库函数（如 `extractvalue()`、`updatexml()`）触发错误，将数据带出到错误信息中。

**攻击Payload：**
```
搜索框输入: ' AND extractvalue(1, concat(0x7e, database()))--
错误信息:   XPATH syntax error: '~security'
```

**攻击效果：** 数据通过错误信息泄露，即使页面没有数据回显位置也能获取数据。

**限制：** 部分WAF会检测 `extractvalue`、`updatexml` 等函数名。

**修复方案：** 参数化查询杜绝所有SQL代码注入路径。

---

### 类型⑤：LIKE通配符注入

**原理：** SQLite 的 LIKE 支持 `%`（匹配任意字符）和 `_`（匹配单个字符）通配符，攻击者可利用通配符进行模糊匹配探测。

**攻击Payload：**
```
搜索框输入: %          → 返回全部用户（等价于无过滤）
搜索框输入: a%         → 返回所有以a开头的用户
搜索框输入: %a%        → 返回所有包含a的用户
搜索框输入: admin_     → 返回admin开头+1字符的所有记录
```

**攻击效果：** 通过通配符组合可盲猜用户名。

**修复方案：** 对用户输入的 `%` 和 `_` 进行转义：
```python
keyword = keyword.replace("%", "\\%").replace("_", "\\_")
```

---

### 类型⑥：堆叠注入（Stacked Queries）

**原理：** 某些数据库（如MySQL、PostgreSQL）支持用 `;` 分隔多条SQL语句，攻击者可执行任意SQL操作。

**攻击Payload：**
```
搜索框输入: '; DELETE FROM users; --
```

**攻击效果：** 如果数据库支持堆叠查询，可能导致**数据删除、表结构修改、权限提升**等严重后果。

**注意：** SQLite 的 `execute()` 默认不支持堆叠查询，但 `executescript()` 支持。

**修复方案：** 参数化查询 + 避免使用 `executescript()` + 最小权限原则。

---

### 类型⑦：INSERT注入

**原理：** 在注册功能的用户名、密码等字段中插入SQL代码，闭合 INSERT 语句实现任意数据插入。

**漏洞代码：**
```python
sql = f"INSERT INTO users VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

**攻击Payload：**
```
用户名:   hacker', 'hack123', 'h@x.com', '999')--
生成SQL:  INSERT INTO users VALUES ('hacker', 'hack123', 'h@x.com', '999')--', ...)
```

**攻击效果：** 向数据库插入恶意数据，甚至可通过子查询窃取其它表数据。

**修复方案：**
```python
# ✅ 参数化查询
sql = "INSERT INTO users VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

---

## 三、漏洞代码 vs 安全代码对比

### 搜索功能

| 维度 | 漏洞版 `app.py` | 安全版 `app_fixed.py` |
|------|-----------------|----------------------|
| SQL构建方式 | `f"...LIKE '%{keyword}%'"` | `"...LIKE ?"` |
| 用户输入角色 | 拼接为SQL代码 | 作为参数传入 |
| `' OR '1'='1` | 变为永真条件 ✅ | 当作普通文本匹配 ❌ |
| `' UNION SELECT...` | 合并到结果 ✅ | 当作普通文本匹配 ❌ |
| 数据库执行 | `c.execute(sql_built)` | `c.execute(sql_safe, params)` |

### 注册功能

| 维度 | 漏洞版 | 安全版 |
|------|--------|--------|
| SQL构建 | `f"VALUES ('{username}')"` | `"VALUES (?)"` |
| username=`hacker')--` | 闭合成功 ✅ | 插入失败 ❌ |
| 输出示例 | `VALUES ('hacker')--', ...)` | `VALUES ('hacker'')--', ...)` 被转义 |

---

## 四、SQL注入防御方案对比

| 防御措施 | 效果 | 实现难度 | 推荐度 |
|----------|------|----------|:------:|
| **参数化查询** `?` | 彻底杜绝注入 | 低 | ⭐⭐⭐⭐⭐ |
| 输入过滤/转义 | 可能被绕过 | 中 | ⭐⭐⭐ |
| WAF/防火墙 | 可被绕过 | 高 | ⭐⭐ |
| 存储过程 | 减少注入面 | 中 | ⭐⭐⭐⭐ |
| ORM框架 | 内置防护 | 低 | ⭐⭐⭐⭐⭐ |

---

## 五、POC命令集（可直接运行测试）

```bash
# 登录获取 session
CSRF=$(curl -s -c c.txt http://localhost:5000/login | grep -oP 'name="_csrf_token" value="\K[^"]+')
curl -s -b c.txt -c c.txt -d "username=admin&password=admin123&_csrf_token=$CSRF" \
  http://localhost:5000/login -o /dev/null

echo "=== 1. UNION注入 ==="
curl -b c.txt "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"

echo "=== 2. OR注入 ==="
curl -b c.txt "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"

echo "=== 3. AND布尔盲注(真) ==="
curl -b c.txt "http://localhost:5000/search?keyword=admin%27%20AND%20%271%27%3D%271"

echo "=== 4. AND布尔盲注(假) ==="
curl -b c.txt "http://localhost:5000/search?keyword=admin%27%20AND%20%271%27%3D%272"

echo "=== 5. LIKE通配符 ==="
curl -b c.txt "http://localhost:5000/search?keyword=%25a%25"

echo "=== 安全版测试(应全部失败) ==="
CSRF2=$(curl -s -c c2.txt http://localhost:5001/login | grep -oP 'name="_csrf_token" value="\K[^"]+')
curl -s -b c2.txt -c c2.txt -d "username=admin&password=admin123&_csrf_token=$CSRF2" \
  http://localhost:5001/login -o /dev/null
curl -b c2.txt "http://localhost:5001/search?keyword=%27%20OR%20%271%27%3D%271" | grep "无搜索结果" && echo "✅ OR注入已被拦截"
```

---

## 六、修复原则总结

```
┌──────────────────────────────────────────┐
│           SQL注入防御铁律                 │
│                                          │
│    ❌ 永远不要用 f-string 拼接 SQL       │
│    ❌ 永远不要相信用户输入               │
│    ✅ 始终使用参数化查询 ? 占位符        │
│    ✅ 最小权限原则（不用 root 连库）     │
│    ✅ 输入校验（类型/长度/格式）         │
│    ✅ 错误信息不暴露给用户               │
└──────────────────────────────────────────┘
```

---

## 七、项目启动

```bash
# 漏洞版（端口5000）
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
export ADMIN_INIT_PASS="admin123" ALICE_INIT_PASS="alice2025"
python3 app.py

# 安全版（端口5001）
python3 app_fixed.py
```

---

*报告生成日期：2026-07-08*
*项目地址：https://github.com/na-asuka/second-day*
