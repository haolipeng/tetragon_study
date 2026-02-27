# Tetragon 反弹 Shell 检测 — 文件访问维度深度分析

## 文档定位

本文档是「Tetragon 反弹 Shell 检测全流程深度分析」系列的第 4 篇（文件访问维度），覆盖通过文件操作监控检测反弹 Shell 辅助行为的全链路分析。

> **前置阅读**: [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md) — Kprobe 框��、FollowFD Action（§2.4.2）、字符串匹配机制（§2.3.1）。

**覆盖的反弹 Shell 类型**：mkfifo 管道链、/dev/tcp 文件访问、memfd_create 无文件执行、/tmp 可疑写入。

---

## 目录

- [第一部分：反弹 Shell 的文件访问特征](#第一部分反弹-shell-的文件访问特征)
- [第二部分：eBPF 内核层源码分析](#第二部分ebpf-内核层源码分析)
- [第三部分：Go 应用层源码分析](#第三部分go-应用层源码分析)
- [第四部分：实战场景与策略](#第四部分实战场景与策略)
- [第五部分：绕过分析与对策](#第五部分绕过分析与对策)

---

## 第一部分：反弹 Shell 的文件访问特征

### 1.1 文件访问行为分析

反弹 Shell 在文件系统层面产生的可检测行为：

| 行为 | 系统调用 | 关联的反弹 Shell 类型 | 检测 Hook |
|------|---------|---------------------|----------|
| **mkfifo 创建** | `mknodat` (mode=S_IFIFO) | Netcat 管道链: `mkfifo /tmp/f; nc ... < /tmp/f \| sh > /tmp/f` | `sys_mknodat` |
| **/dev/tcp 访问** | `openat` → `fd_install` | Bash: `exec 5<>/dev/tcp/IP/PORT` | `fd_install` |
| **memfd_create** | `memfd_create` | 无文件执行: 在内存中创建匿名文件 | `sys_memfd_create` |
| **/tmp 写入** | `openat` + `write` | 落盘型后门、staging 脚本 | `security_file_permission` |
| **可疑脚本创建** | `openat(O_CREAT)` | 创建 `/tmp/shell.sh` 等 | `fd_install`, `security_path_mknod` |
| **敏感文件读取** | `openat` | 信息收集: `/etc/passwd`, `/etc/shadow` | `security_file_permission` |

### 1.2 fd_install 作为核心监控点

`fd_install` 是 Linux 内核中将文件描述符安装到进程 FD 表的函数。每当一个文件被成功打开（`open`/`openat`/`socket`/`accept` 等），内核都会调用 `fd_install(fd, file)` 将新的文件描述符注册到当前进程。

```
用户空间: openat("/tmp/shell.sh", O_CREAT|O_WRONLY)
    │
    ▼
内核空间:
    do_sys_openat2()
    → do_filp_open()  // 打开文件
    → fd_install(fd, file)  // 将 fd 安装到进程
        │
        └─ Tetragon Kprobe 触发
           参数: fd(int), file(struct file*)
           从 file→f_path 提取路径
```

`fd_install` 的优势：
- 统一入口：覆盖 open/openat/creat/socket/accept 等多种 FD 创建方式
- 包含 file 结构体：可以提取完整文件路径
- 配合 FollowFD 使用：建立 FD→文件路径映射，支持后续 CopyFD（Doc 3）

---

## 第二部分：eBPF 内核层源码分析

### 2.1 fd_install Hook

**参数定义**:

```
fd_install(unsigned int fd, struct file *file)
    参数 0: fd   → int 类型
    参数 1: file → file 类型（Tetragon 自动提取路径）
```

**file 类型参数的路径提取**: `bpf/process/types/basic.h` 中的路径处理

当参数类型为 `file_ty` 时，BPF 侧通过 `get_path()` 函数从 `struct file` 的 `f_path` 成员提取文件路径：

```c
// get_path() 检查参数类型并获取 path 结构体
// 对于 file_ty: path = &file->f_path
// 对于 path_ty: path = arg (直接使用)

// copy_path() 使用 d_path_local() 解析完整路径
FUNC_INLINE long copy_path(char *args, const struct path *arg)
{
    int size = 0, flags = 0;
    char *buffer;

    buffer = d_path_local(arg, &size, &flags);
    if (!buffer)
        return 0;

    return store_path(args, buffer, arg, size, flags);
}
```

**store_path 输出格式**: `bpf/process/types/basic.h:380-408`

```c
// 路径数据格式:
// -----------------------------------------
// | 4 bytes | N bytes | 4 bytes | 2 bytes |
// | pathlen |  path   |  flags  |  i_mode |
// -----------------------------------------
```

### 2.2 文件路径匹配

文件路径匹配使用与字符串匹配相同的基础设施（详见 Doc 0 §2.3.1），但通过 `filter_file_buf()` 函数处理：

**源码位置**: `bpf/process/types/basic.h:937-964`

```c
FUNC_LOCAL long
filter_file_buf(struct selector_arg_filter *filter, struct string_buf *args)
{
    // 空路径（如未命名管道）不匹配
    if (args->len == 0)
        return 0;

    switch (filter->op) {
    case op_filter_eq:
    case op_filter_neq:
        match = filter_char_buf_equal(filter, args->buf, args->len);
        break;
    case op_filter_str_prefix:
    case op_filter_str_notprefix:
        match = filter_char_buf_prefix(filter, args->buf, args->len);
        break;
    case op_filter_str_postfix:
    case op_filter_str_notpostfix:
        match = filter_char_buf_postfix(filter, args->buf, args->len);
        break;
    }

    return is_not_operator(filter->op) ? !match : match;
}
```

**支持的操作符**:

| 操作符 | BPF 实现 | 适用场景 |
|--------|---------|---------|
| `Equal` | `filter_char_buf_equal()` → Hash Map 精确匹配 | 匹配特定文件路径 |
| `Prefix` | `filter_char_buf_prefix()` → LPM Trie 前缀匹配 | 匹配目录（如 `/tmp/`） |
| `Postfix` | `filter_char_buf_postfix()` → 反转 LPM Trie | 匹配文件扩展名（如 `.sh`） |
| `NotPrefix` | `filter_char_buf_prefix()` → 取反 | 排除特定目录 |

### 2.3 openat/openat2 系统调用监控

通过 Generic Kprobe 挂钩 `sys_openat` 可以使用 `filename_ty` 类型捕获打开的文件路径：

**filename_ty 参数读取**: `bpf/process/generic_calls.h:270-279`

```c
case filename_ty: {
    struct filename *file;

    // filename_ty: 内核 struct filename* → 读取 name 字段
    probe_read(&file, sizeof(file), &arg);
    probe_read(&arg, sizeof(arg), &file->name);
}
    fallthrough;
case string_type:
    size = copy_strings(args, (char *)arg, MAX_STRING);
    break;
```

`filename_ty` 类型专门用于系统调用中的文件名参数（`struct filename*`），它自动解引用 `filename->name` 获取实际的路径字符串。

### 2.4 Fileless 执行检测（i_nlink）

无文件执行检测通过 `bpf_execve_bprm_commit_creds.c` 中的 `i_nlink` 检查实现（详见 Doc 1 §2.5）。

**源码位置**: `bpf/process/bpf_execve_bprm_commit_creds.c:70-76`

```c
// 读取执行文件的 inode 硬链接数
BPF_CORE_READ_INTO(&heap->info.i_nlink, file, f_inode, __i_nlink);

// i_nlink == 0: 文件没有磁盘链接（memfd_create 创建的匿名文件）
// i_nlink > 0:  正常文件
```

**memfd_create 系统调用监控**:

```yaml
kprobes:
- call: "sys_memfd_create"
  syscall: true
  args:
  - index: 0
    type: "string"     # name（描述性名称，非路径）
  - index: 1
    type: "int"        # flags
```

---

## 第三部分：Go 应用层源码分析

### 3.1 File 类型参数解析

**Go 侧处理**: `pkg/sensors/tracing/args_linux.go`

```
handleGenericKprobe():
    │ 参数类型为 gt.GenericFileType:
    │   1. 读取 4 字节路径长度
    │   2. 读取路径字符串
    │   3. 读取 4 字节 flags
    │   4. 读取 2 字节 i_mode（文件类型+权限）
    │   → 构建 MsgGenericKprobeArgFile {path, flags}
```

**Protobuf 输出**:

```json
{
  "process_kprobe": {
    "function_name": "fd_install",
    "args": [
      {"int_arg": {"value": 5}},
      {"file_arg": {"path": "/tmp/f", "flags": "O_RDWR"}}
    ]
  }
}
```

### 3.2 Path Resolution 机制

Tetragon 的路径解析使用内核的 `d_path()` 函数（BPF 侧通过 `d_path_local()` wrapper 调用）。这确保返回的路径是完整的、经过挂载点解析的绝对路径。

特殊路径处理：
- **匿名文件** (memfd): 路径为空或包含 `memfd:` 前缀
- **管道**: 路径包含 `pipe:` 前缀
- **Socket**: 路径包含 `socket:` 前缀
- **符号链接**: 解析为实际路径

---

## 第四部分：实战场景与策略

### 4.1 检测 mkfifo 创建

**场景**: 检测 `mkfifo` 创建命名管道，这是 Netcat 管道链反弹 Shell 的关键步骤。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-mkfifo"
spec:
  kprobes:
  - call: "sys_mknodat"
    syscall: true
    args:
    - index: 0
      type: "int"       # dirfd（AT_FDCWD = -100）
    - index: 1
      type: "string"    # pathname
    - index: 2
      type: "int"       # mode
    selectors:
    # S_IFIFO = 0010000 = 4096
    - matchArgs:
      - index: 2
        operator: "Mask"
        values:
        - "4096"         # mode & S_IFIFO != 0
```

**事件观察**:

```bash
# 检测 mkfifo 创建
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "sys_mknodat")
  | {
      time: .time,
      binary: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      pathname: .process_kprobe.args[1].string_arg,
      mode: .process_kprobe.args[2].int_arg.value
    }'
```

### 4.2 检测可疑临时文件写入

**场景**: 检测在 `/tmp`、`/dev/shm`、`/var/tmp` 等可写目录中创建可疑文件。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-suspicious-file-write"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"        # MAY_WRITE = 0x02
    returnArg:
      index: 0
      type: "int"
    returnArgAction: "Post"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/tmp/"
        - "/dev/shm/"
        - "/var/tmp/"
      - index: 1
        operator: "Equal"
        values:
        - "2"             # MAY_WRITE
```

**使用 fd_install 监控文件打开**:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-tmp-file-creation"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/tmp/"
        - "/dev/shm/"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/bash"
        - "/bin/bash"
        - "/usr/bin/nc"
        - "/usr/bin/python3"
        - "/usr/bin/curl"
        - "/usr/bin/wget"
```

### 4.3 检测 memfd_create 无文件执行

**场景**: 检测使用 memfd_create 创建匿名内存文件的行为。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-memfd-create"
spec:
  kprobes:
  - call: "sys_memfd_create"
    syscall: true
    args:
    - index: 0
      type: "string"    # name
    - index: 1
      type: "int"       # flags
```

**事件观察**:

```bash
# 检测 memfd_create 调用
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "sys_memfd_create")
  | {
      time: .time,
      binary: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      parent: .process_kprobe.parent.binary,
      memfd_name: .process_kprobe.args[0].string_arg,
      flags: .process_kprobe.args[1].int_arg.value
    }'
```

**结合无文件执行检测**（通过 process_exec 事件的 i_nlink 字段）:

```bash
# 检测 memfd_create + 无文件执行的完整链
# 步骤 1: 监控 memfd_create → 记录 PID
# 步骤 2: 监控 process_exec 中 i_nlink==0 → 确认无文件执行
tetra getevents -o json | jq '
  if .process_kprobe.function_name == "sys_memfd_create" then
    {type: "MEMFD_CREATE",
     pid: .process_kprobe.process.pid.value,
     binary: .process_kprobe.process.binary,
     name: .process_kprobe.args[0].string_arg}
  elif (.process_exec != null and
        .process_exec.process.binary_properties.file.inode.links == 0) then
    {type: "FILELESS_EXEC",
     pid: .process_exec.process.pid.value,
     binary: .process_exec.process.binary,
     parent: .process_exec.parent.binary}
  else empty end'
```

### 4.4 监控敏感文件访问

**场景**: 反弹 Shell 获取后，攻击者通常会进行信息收集，访问 `/etc/passwd`、`/etc/shadow` 等敏感文件。

基于 `examples/tracingpolicy/filename_monitoring.yaml`:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-sensitive-file-access"
spec:
  kprobes:
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
        - "/etc/gshadow"
        - "/root/.ssh/"
        - "/home/"
      - index: 1
        operator: "Equal"
        values:
        - "4"             # MAY_READ = 0x04
```

### 4.5 监控符号链接创建

基于 `examples/tracingpolicy/symlink-observe.yaml`:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-suspicious-symlink"
spec:
  kprobes:
  - call: "sys_symlinkat"
    syscall: true
    args:
    - index: 0
      type: "string"    # target（链接目标）
    - index: 1
      type: "int"       # newdirfd
    - index: 2
      type: "string"    # linkpath（链接路径）
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/"
        - "/usr/bin/"
        - "/usr/sbin/"
```

---

## 第五部分：绕过分析与对策

### 5.1 绕过技术

| 绕过技术 | 原理 | 效果 |
|---------|------|------|
| **纯内存操作** | 不写入任何文件，全部在内存中完成 | 绕过文件写入检测 |
| **符号链接伪装** | 通过 symlink 指向合法路径 | 可能绕过路径匹配 |
| **非常见路径** | 使用 `/run/user/`、`/sys/fs/cgroup/` 等路径 | 绕过 `/tmp` 前缀检测 |
| **O_TMPFILE** | 使用 `open(dir, O_TMPFILE\|O_WRONLY, mode)` 创建无名临时文件 | 绕过路径匹配 |
| **fmemopen** | 使用 C 库函数在内存中创建 FILE 流 | 不触发 fd_install |

### 5.2 对策

#### 5.2.1 symlink/hardlink 监控

```yaml
# 同时监控 symlink 和 hardlink 创建
kprobes:
- call: "sys_symlinkat"
  syscall: true
  args:
  - index: 0
    type: "string"
  - index: 2
    type: "string"
- call: "sys_linkat"
  syscall: true
  args:
  - index: 1
    type: "string"    # oldpath
  - index: 3
    type: "string"    # newpath
```

#### 5.2.2 联合进程维度

文件访问检测本身通常产生较多事件。通过联合进程维度（matchBinaries）可以显著减少噪声：

```yaml
# 仅监控 Shell/解释器创建的临时文件
selectors:
- matchBinaries:
  - operator: "In"
    values:
    - "/usr/bin/bash"
    - "/usr/bin/python3"
    - "/usr/bin/nc"
  matchArgs:
  - index: 1
    operator: "Prefix"
    values:
    - "/tmp/"
```

#### 5.2.3 /dev/shm 监控

`/dev/shm` 是共享内存文件系统，常被攻击者用作暂存区域。它不受磁盘空间限制且通常不被传统安全工具监控：

```yaml
# 监控 /dev/shm 中的文件操作
selectors:
- matchArgs:
  - index: 0
    operator: "Prefix"
    values:
    - "/dev/shm/"
```

#### 5.2.4 检测层次总结

| 检测层次 | 机制 | 覆盖范围 | 误报率 |
|---------|------|---------|-------|
| fd_install + Prefix | 文件打开路径 | 所有文件打开 | 高 |
| security_file_permission | 读/写权限检查 | 所有文件访问 | 中 |
| sys_mknodat + S_IFIFO | mkfifo 创建 | FIFO 管道 | 低 |
| sys_memfd_create | 匿名内存文件 | 无文件执行 | 低 |
| i_nlink == 0 (execve) | 无链接文件执行 | 所有 execve | 低 |

文件访问维度最适合作为辅助检测手段，与进程执行（Doc 1）、网络连接（Doc 2）、FD 重定向（Doc 3）结合使用可以构建完整的反弹 Shell 检测方案（详见 Doc 5）。
