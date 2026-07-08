# 用户信息管理平台 — SQL注入学习靶场

基于 **Python Flask** 的 SQL 注入学习与安全实践项目。包含漏洞版和安全版两套代码，支持 **7 种 SQL 注入类型**的演示与测试。

## 快速开始

```bash
git clone https://github.com/na-asuka/second-day.git
cd second-day
pip install -r requirements.txt

# 启动漏洞版（端口5000）
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
export ADMIN_INIT_PASS="admin123" ALICE_INIT_PASS="alice2025"
python3 app.py

# 或启动安全版（端口5001）
python3 app_fixed.py
```

| 版本 | 端口 | SQL方式 | SQL注入 |
|------|:----:|---------|:-------:|
| 漏洞版 `app.py` | 5000 | f-string 拼接 | ✅ 可注入 |
| 安全版 `app_fixed.py` | 5001 | 参数化查询 `?` | ❌ 已修复 |

## 支持的SQL注入类型

| # | 注入类型 | 搜索框输入 | 效果 |
|:-:|----------|-----------|------|
| 1 | **UNION注入** | `' UNION SELECT 1,'黑客','h@x.com','666'--` | 伪造数据插入结果 |
| 2 | **OR注入** | `' OR '1'='1` | 返回全部用户 |
| 3 | **AND布尔盲注(真)** | `admin' AND '1'='1` | 正常返回数据 |
| 4 | **AND布尔盲注(假)** | `admin' AND '1'='2` | 无数据返回 |
| 5 | **LIKE通配符** | `%a%` | 模糊匹配所有含a的用户 |
| 6 | **堆叠注入** | `'; DELETE FROM users--` | 尝试执行多条语句 |
| 7 | **INSERT注入(注册)** | 用户名: `hacker', '123', 'h@x.com', '999')--` | 闭合INSERT语句 |

## 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

## 项目结构

```
├── app.py                        # 漏洞版（f-string拼接SQL）
├── app_fixed.py                  # 安全版（参数化查询）
├── templates/
│   ├── base.html                 # 基础模板
│   ├── login.html                # 登录页
│   ├── index.html                # 漏洞版首页（显示SQL+注入用例）
│   ├── index_safe.html           # 安全版首页
│   ├── register.html             # 漏洞版注册页（显示SQL）
│   └── register_safe.html        # 安全版注册页
├── static/css/style.css          # 样式文件
├── SQL_INJECTION_REPORT.md       # SQL注入类型分析与修复报告
├── README.md                     # 本文件
└── requirements.txt              # 依赖
```

## 安全功能

- bcrypt 密码哈希
- CSRF 令牌防护
- 暴力破解限制（IP+用户名限流）
- 会话安全（HttpOnly + SameSite）
- 安全响应头（X-Frame-Options + CSP）
- HTTPS 可选跳转
- 审计日志（文件轮转）
