# 用户信息管理平台

基于 **Python Flask** 的简易用户信息管理登录系统，专注于安全实践的教学演示项目。

## 功能特性

- 用户登录 / 登出
- 首页展示当前登录用户的完整信息
- 基于 session 的会话管理
- 完整的审计日志记录

## 安全架构

| 安全措施 | 实现方式 |
|----------|----------|
| 密码哈希 | `passlib.hash.bcrypt` — 高计算成本，抗 GPU/ASIC 暴力破解 |
| 敏感配置隔离 | 密钥与初始密码全部通过环境变量注入，源码零硬编码 |
| CSRF 防护 | 自定义 CSRF 令牌方案，`secrets.compare_digest()` 常量时间比对 |
| 暴力破解防护 | 基于 `IP + 用户名` 双层限流，5 分钟内错误 5 次自动锁定 5 分钟 |
| 强密码策略 | 最小 8 位，必须包含大写字母、小写字母、数字、特殊符号 |
| HTTPS 支持 | 设置 `FORCE_HTTPS` 环境变量后自动 301 跳转 HTTPS |
| Session 安全 | `HttpOnly` / `SameSite=Lax` / `Secure`（可选）/ 2 小时过期 |
| 审计日志 | 记录登录成功/失败/锁定/登出事件，`RotatingFileHandler` 自动轮转 |

## 快速开始

### 前置条件

- Python 3.8+
- `passlib` 库

### 安装

```bash
git clone git@github.com:na-asuka/second-day.git
cd second-day
pip install flask passlib
```

### 配置与启动

```bash
# 1. 生成随机密钥
export SECRET_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")

# 2. 设置初始密码（生产环境请使用强密码）
export ADMIN_INIT_PASS="your_admin_password"
export ALICE_INIT_PASS="your_alice_password"

# 3. （可选）启用 HTTPS
export FORCE_HTTPS=true

# 4. 启动服务
python3 app.py
```

服务启动后访问 **http://127.0.0.1:5000**

## 项目结构

```
├── app.py                  # Flask 主应用
├── templates/
│   ├── base.html           # 基础模板（导航栏）
│   ├── index.html          # 首页
│   └── login.html          # 登录页
├── static/
│   └── css/
│       └── style.css       # 样式文件
└── README.md
```
