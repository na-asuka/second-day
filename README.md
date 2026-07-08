# 用户信息管理平台 — SQL注入学习靶场

基于 **Python Flask** 的 SQL 注入学习与安全实践项目。包含漏洞版和安全版两套代码，支持完整 **SQL 注入攻击链**（判断注入点→列数→回显→库名→表名→列名→数据）的演示与测试。

## 快速开始

```bash
git clone https://github.com/na-asuka/second-day.git
cd second-day
pip install -r requirements.txt

# 启动漏洞版（端口5000）
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
python3 app.py

# 或启动安全版（端口5001）
python3 app_fixed.py
```

| 版本 | 端口 | SQL方式 | SQL注入 |
|------|:----:|---------|:-------:|
| 漏洞版 `app.py` | 5000 | f-string 拼接 | ✅ 可注入 |
| 安全版 `app_fixed.py` | 5001 | 参数化查询 `?` | ❌ 已修复 |

## 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

## 项目结构

```
├── app.py                        # 漏洞版（f-string拼接SQL，端口5000）
├── app_fixed.py                  # 安全版（参数化查询，端口5001）
├── templates/
│   ├── base.html                 # 基础模板
│   ├── login.html                # 登录页
│   ├── index.html                # 漏洞版首页
│   ├── index_safe.html           # 安全版首页
│   ├── register.html             # 漏洞版注册页
│   └── register_safe.html        # 安全版注册页
├── static/css/style.css          # 样式文件
├── SQL_INJECTION_REPORT.md       # SQL注入类型分析与修复报告
├── README.md                     # 本文件
└── requirements.txt              # 依赖
```

## 安全功能

- bcrypt 密码哈希（安全版全流程哈希存储）
- CSRF 令牌防护
- 暴力破解限制（IP+用户名限流）
- 会话安全（HttpOnly + SameSite + 2h过期）
- 安全响应头（X-Frame-Options + CSP）
- HTTPS 可选跳转
- 审计日志（文件轮转）
