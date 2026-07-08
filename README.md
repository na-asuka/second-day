# 用户信息管理平台 — 安全版

基于 **Python Flask** 的安全用户管理系统。全部 SQL 使用参数化查询 `?` 占位符，防止 SQL 注入。

## 快速启动

```bash
git clone https://github.com/na-asuka/second-day.git
cd second-day
pip install -r requirements.txt
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
python3 app.py
```

访问 **http://127.0.0.1:5000**

## 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

## 安全功能

- 参数化查询 — 防止 SQL 注入
- bcrypt 密码哈希
- CSRF 令牌防护
- 暴力破解限制（IP+用户名限流）
- 会话安全（HttpOnly + SameSite）
- 安全响应头（X-Frame-Options + CSP）
- HTTPS 可选跳转
- 审计日志记录

## SQL注入攻击链（学习参考）

| 步骤 | Payload | 说明 |
|:----:|---------|------|
| 1 | `'` | 判断是否存在注入点 |
| 2 | `' OR '1'='1` | 确认字符型注入 |
| 3 | `' ORDER BY 3 --` | 探测列数 |
| 4 | `' UNION SELECT 1,2,3 --` | 确定回显位置 |
| 5 | `' UNION SELECT 1,database(),3 --` | 获取库名 |
| 6 | `' UNION SELECT 1,group_concat(name),3 FROM sqlite_master --` | 获取表名 |
| 7 | `' UNION SELECT 1,group_concat(name),3 FROM pragma_table_info('users') --` | 获取列名 |
| 8 | `' UNION SELECT 1,password,3 FROM users --` | 获取数据 |

> 以上注入在参数化查询下**全部被拦截**，仅作为学习参考。

## 项目结构

```
├── app.py                        # Flask 主应用
├── templates/
│   ├── base.html                 # 基础模板
│   ├── login.html                # 登录页
│   ├── index.html                # 首页
│   └── register.html             # 注册页
├── static/css/style.css          # 样式文件
├── SQL_INJECTION_REPORT.md       # SQL注入类型分析报告
└── requirements.txt              # 依赖
```
