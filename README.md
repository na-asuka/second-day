# 用户管理系统 — 安全版 v3.0

基于 **Python Flask** 的安全用户管理系统。纵深防御：水平越权 + 支付逻辑 + 垂直越权。

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

## 纵深防御架构

### 水平越权（3层防御）
- 个人中心 `GET /profile` — 未登录跳转，默认查自己
- 指定 `user_id` 时强制校验 session 归属
- admin 例外可查看全部用户

### 支付逻辑（6层防御）
- `user_id` 从 session 获取，不信任客户端
- 固定套餐金额（10/50/100/500元），服务端映射
- 金额强制为正整数
- 数据库事务 + 行锁 `FOR UPDATE` 防并发
- 充值记录写入 audit 表
- CSRF 令牌校验

### 垂直越权（3层防御）
- `@admin_required` 装饰器校验 admin 角色
- 普通用户访问后台返回 403
- 导航栏 admin 链接仅对管理员可见

### 其他安全措施
- 参数化查询防 SQL 注入
- bcrypt 密码哈希
- CSRF 令牌防护
- 暴力破解限制（IP+用户名限流）
- 会话安全（HttpOnly + SameSite）
- 安全响应头（X-Frame-Options + nosniff）
- 文件上传 WAF 模拟（扩展名 + 内容检测）
- 路径穿越防护（os.path.basename）
- 审计日志（文件轮转）

## 项目结构

```
├── app.py                        # Flask 主应用
├── templates/
│   ├── base.html                 # 基础模板
│   ├── login.html                # 登录页
│   ├── index.html                # 首页
│   ├── register.html             # 注册页
│   ├── upload.html               # 上传页
│   ├── profile.html              # 个人中心
│   └── admin.html                # 管理后台
├── static/
│   ├── css/style.css             # 样式文件
│   └── uploads/                  # 上传目录
└── requirements.txt              # 依赖
```
