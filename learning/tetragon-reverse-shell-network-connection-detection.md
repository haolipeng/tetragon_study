# Tetragon 反弹 Shell 检测 — 网络连接维度深度分析

## 文档定位

本文档是「Tetragon 反弹 Shell 检测全流程深度分析」系列的第 2 篇（网络连接维度），覆盖通过网络连接监控检测反弹 Shell 外连行为的全链路分析。

> **前置阅读**: 本文档假设读者已阅读 [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md)，了解 Kprobe 框架、Tail Call 管道、选择器编译机制和事件输出管道。本文将从网络维度特定的 Hook 点和数据结构开始分析。

**覆盖的反弹 Shell 类型**：所有类型 — 每种反弹 Shell 都需要建立网络连接，这使网络监控成为覆盖面最广的检测维度。

---

## 目录

- [第一部分：反弹 Shell 的网络特征](#第一部分反弹-shell-的网络特征)
- [第二部分：eBPF 内核层源码分析](#第二部分ebpf-内核层源码分析)
- [第三部分：Go 应用层源码分析](#第三部分go-应用层源码分析)
- [第四部分：实战场景与策略](#第四部分实战场景与策略)
- [第五部分：绕过分析与对策](#第五部分绕过分析与对策)

---

## 第一部分：反弹 Shell 的网络特征

### 1.1 网络连接模式

反弹 Shell 的网络行为可分为三种基本模式：

| 模式 | 连接方向 | 典型工具 | Hook 点 |
|------|---------|---------|---------|
| **反向连接**（最常见） | 目标 → 攻击者 | bash /dev/tcp, nc, python | `tcp_connect` |
| **正向绑定** | 攻击者 → 目标（监听端口） | `nc -lvp`, `socat LISTEN` | `inet_csk_listen_start` |
| **隧道/代理** | 通过中间层（HTTP/DNS/ICMP） | `dns2tcp`, `icmpsh`, `chisel` | `security_socket_connect` |

### 1.2 Hook 点选择

Tetragon 提供多个内核 Hook 点来监控网络连接：

| Hook 点 | 层级 | 参数 | 优势 | 适用场景 |
|---------|------|------|------|---------|
| `tcp_connect` | 传输层函数 | `sock` | 高效、仅 TCP、包含完整五元组 | TCP ���连检测 |
| `tcp_close` | 传输层函数 | `sock` | 检测连接关闭 | 连接生命周期 |
| `tcp_sendmsg` | 传输层函数 | `sock`, `size` | 检测数据传输量 | 数据泄露检测 |
| `inet_csk_listen_start` | 传输层函数 | `sock` | 检测端口监听 | 正向绑定 Shell |
| `security_socket_connect` | LSM Hook | `socket`, `sockaddr` | 全协议覆盖（TCP+UDP+...）| 最全面的检测 |
| `sk_alloc` / `__sk_free` | Socket 生命周期 | `sock` (return) | TrackSock 机制 | Socket 关联跟踪 |

### 1.3 网络参数与反�� Shell 特征

| 特征 | 正常连接 | 反弹 Shell 连接 |
|------|---------|----------------|
| 目标端口 | 80, 443, 3306 等标准端口 | 4444, 8888, 1337, 31337 等异常端口 |
| 目标地址 | 通常为内网或已知服务 | 外网 IP 或未知地址 |
| 发起进程 | Web 服务、数据库客户端等 | bash, nc, python, perl 等 |
| 连接频率 | 服务启动时建立 | 被入侵后突然出现 |
| 进程树 | 正常服务进程树 | Web服务器→解释器→Shell |

---

## 第二部分：eBPF 内核层源码分析

### 2.1 Socket 数据结构提取

当 Kprobe 捕获到 `sock` 类型参数时，BPF 侧通过 `set_event_from_sock()` 从内核 `struct sock` 中提取网络信息。

**源码位置**: `bpf/process/types/sock.h:26-67`

```c
FUNC_INLINE void
set_event_from_sock(struct sk_type *event, struct sock *sk)
{
    struct sock_common *common = (struct sock_common *)sk;

    // 保存 sock 内核地址（用于 TrackSock 关联）
    event->sockaddr = (__u64)sk;

    // 提取协议族（AF_INET=2, AF_INET6=10）
    probe_read(&event->tuple.family, sizeof(event->tuple.family),
               _(&common->skc_family));

    // 提取 TCP 状态
    probe_read(&event->state, sizeof(event->state),
               _((const void *)&common->skc_state));

    // 提取 Socket 类型（SOCK_STREAM=1, SOCK_DGRAM=2）
    probe_read(&event->type, sizeof(event->type), _(&sk->sk_type));

    // 提取协议号（IPPROTO_TCP=6, IPPROTO_UDP=17）
    probe_read(&event->tuple.protocol, sizeof(event->tuple.protocol),
               _(&sk->sk_protocol));

    // 内核 < v5.6 的协议字段兼容处理
    if (bpf_core_field_size(sk->sk_protocol) == 4) {
        event->tuple.protocol = event->tuple.protocol >> 8;
    }

    // 提取 mark 和 priority
    probe_read(&event->mark, sizeof(event->mark), _(&sk->sk_mark));
    probe_read(&event->priority, sizeof(event->priority), _(&sk->sk_priority));

    // 按地址族提取 IP 地址
    switch (event->tuple.family) {
    case AF_INET:
        probe_read(&event->tuple.saddr, IPV4LEN, _(&common->skc_rcv_saddr));
        probe_read(&event->tuple.daddr, IPV4LEN, _(&common->skc_daddr));
        break;
    case AF_INET6:
        probe_read(&event->tuple.saddr, IPV6LEN, _(&common->skc_v6_rcv_saddr));
        probe_read(&event->tuple.daddr, IPV6LEN, _(&common->skc_v6_daddr));
    }

    // 提取端口
    probe_read(&event->tuple.sport, sizeof(event->tuple.sport),
               _(&common->skc_num));
    probe_read(&event->tuple.dport, sizeof(event->tuple.dport),
               _(&common->skc_dport));
    event->tuple.dport = bpf_ntohs(event->tuple.dport); // 网络字节序→主机字节序
}
```

**数据提取路径映射**：

```
内核 struct sock / struct sock_common
    │
    ├── skc_family       ──→ tuple.family     (AF_INET/AF_INET6)
    ├── skc_state        ──→ state            (TCP_ESTABLISHED 等)
    ├── sk_type          ──→ type             (SOCK_STREAM/SOCK_DGRAM)
    ├── sk_protocol      ──→ tuple.protocol   (IPPROTO_TCP/IPPROTO_UDP)
    ├── skc_rcv_saddr    ──→ tuple.saddr      (IPv4 源地址)
    ├── skc_daddr        ──→ tuple.daddr      (IPv4 目标地址)
    ├── skc_v6_rcv_saddr ──→ tuple.saddr      (IPv6 源地址)
    ├── skc_v6_daddr     ──→ tuple.daddr      (IPv6 目标地址)
    ├── skc_num          ──→ tuple.sport      (源端口，主机字节序)
    └── skc_dport        ──→ tuple.dport      (目标端口，需 ntohs)
```

对于 `sockaddr` 类型参数（用于 `security_socket_connect`），使用 `set_event_from_sockaddr_in()`：

**源码位置**: `bpf/process/types/sockaddr.h:20-45`

```c
FUNC_INLINE void
set_event_from_sockaddr_in(struct sockaddr_in_type *event, struct sockaddr *address)
{
    memset(event, 0, sizeof(*event));
    probe_read(&event->sin_family, sizeof(event->sin_family), _(&address->sa_family));

    switch (event->sin_family) {
    case AF_INET:
        probe_read(&addr, sizeof(addr), _(&ipv4->sin_addr));
        event->sin_addr[0] = addr;
        probe_read(&event->sin_port, sizeof(event->sin_port), _(&ipv4->sin_port));
        break;
    case AF_INET6:
        probe_read(&event->sin_addr, sizeof(event->sin_addr), _(&ipv6->sin6_addr));
        probe_read(&event->sin_port, sizeof(event->sin_port), _(&ipv6->sin6_port));
        break;
    }
    event->sin_port = bpf_ntohs(event->sin_port);
}
```

对于 `socket` 类型参数，通过 `set_event_from_socket()` 间接调用 `set_event_from_sock()`：

**源码位置**: `bpf/process/types/socket.h:14-22`

```c
FUNC_INLINE void
set_event_from_socket(struct sk_type *event, struct socket *sock)
{
    struct sock *sk;
    probe_read(&sk, sizeof(sk), _(&sock->sk));
    if (sk)
        set_event_from_sock(event, sk);
}
```

### 2.2 网络参数过滤机制

网络参数过滤是反弹 Shell 网络检测的核心。BPF 侧通过 `filter_inet()` 函数实现。

**源码位置**: `bpf/process/types/basic.h:1029-1123`

```c
FUNC_LOCAL long
filter_inet(struct selector_arg_filter *filter, char *args)
{
    struct tuple_type *tuple = 0;
    // ...

    // 1. 根据参数类型获取 tuple
    switch (filter->type) {
    case sock_type:
    case socket_type:
        sk = (struct sk_type *)args;
        tuple = &sk->tuple;
        break;
    case sockaddr_type:
        address = (struct sockaddr_in_type *)args;
        // 将 sockaddr 字段映射到 tuple
        t.family = address->sin_family;
        t.sport = address->sin_port;
        t.saddr[0] = address->sin_addr[0];
        tuple = &t;
        break;
    }

    // 2. 根据操作符选择要比较的字段
    switch (filter->op) {
    case op_filter_saddr:
    case op_filter_notsaddr:
        write_ipv6_addr(addr, tuple->saddr);  // 取源地址
        break;
    case op_filter_daddr:
    case op_filter_notdaddr:
        write_ipv6_addr(addr, tuple->daddr);  // 取目标地址
        break;
    case op_filter_sport:
    case op_filter_notsport:
        port = tuple->sport;                  // 取源端口
        break;
    case op_filter_dport:
    case op_filter_notdport:
        port = tuple->dport;                  // 取目标端口
        break;
    case op_filter_protocol:
        value = tuple->protocol;              // 取协议号
        break;
    case op_filter_family:
        value = tuple->family;                // 取地址族
        break;
    case op_filter_state:
        value = sk->state;                    // 取 TCP 状态
        break;
    }

    // 3. 执行匹配
    switch (filter->op) {
    case op_filter_sport:
    case op_filter_dport:
        return filter_32ty_map(filter, (char *)&port);  // Hash Map 端口匹配
    case op_filter_sportpriv:
    case op_filter_dportpriv:
        return port < 1024;                              // 特权端口检查
    case op_filter_saddr:
    case op_filter_daddr:
    case op_filter_notsaddr:
    case op_filter_notdaddr:
        return filter_addr_map(filter, addr, tuple->family); // LPM Trie CIDR 匹配
    case op_filter_protocol:
    case op_filter_family:
        return filter_32ty_map(filter, (char *)&value);  // Hash Map 值匹配
    case op_filter_state:
        return filter_32ty_map(filter, (char *)&value);  // TCP 状态匹配
    }
}
```

#### 2.2.1 地址匹配：LPM Trie CIDR

**源码位置**: `bpf/process/addr_lpm_maps.h`

LPM（Longest Prefix Match）Trie 是 BPF 提供的专用 Map 类型，天然支持 CIDR 地址匹配。

```c
// IPv4 LPM Trie 条目
struct addr4_lpm_trie {
    __u32 prefix;   // CIDR 前缀长度（/8, /16, /24, /32）
    __u32 addr;     // IPv4 地址（网络字节序）
};

// IPv6 LPM Trie 条目
struct addr6_lpm_trie {
    __u32 prefix;   // CIDR 前缀长度（/128 等）
    __u32 addr[4];  // IPv6 地址（4个u32）
};
```

**匹配流程**:

```
YAML: operator: "NotDAddr"
      values: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      │
      ▼
Go 编译:
    1. 解析 CIDR → net.IPNet
    2. 创建 LPM_TRIE Map
    3. 插入条目: {prefix=8, addr=10.0.0.0}, {prefix=12, addr=172.16.0.0}, ...
    4. 写入 addr4lpm_maps[map_idx] = trie_map_fd
      │
      ▼
BPF 运行时:
    1. filter_addr_map() 被调用
    2. 从事件 tuple 中提取 daddr
    3. 构造查询 key: {prefix=32, addr=actual_daddr}
    4. 调用 map_lookup_elem(addrmap, &key)
    5. LPM Trie 自动执行最长前缀匹配
    6. NotDAddr: 返回 !exists（不在私有地址段则匹配）
```

**源码位置**: `bpf/process/types/basic.h:987-1024`

```c
FUNC_INLINE long
filter_addr_map(struct selector_arg_filter *filter, __u64 *addr, __u16 family)
{
    void *addrmap;
    __u32 *map_idxs = (__u32 *)&filter->value;

    switch (family) {
    case AF_INET:
        map_idx = map_idxs[0];
        addrmap = map_lookup_elem(&addr4lpm_maps, &map_idx);
        if (!addrmap)
            return filter_addr_op_mod(filter->op, 0);
        arg4.prefix = 32;       // 用 /32 查询（精确匹配输入地址）
        arg4.addr = addr[0];    // 被检查的地址
        arg = &arg4;
        break;
    case AF_INET6:
        map_idx = map_idxs[1];
        addrmap = map_lookup_elem(&addr6lpm_maps, &map_idx);
        // ...同理
        break;
    }

    long exists = (long)map_lookup_elem(addrmap, arg);
    return filter_addr_op_mod(filter->op, exists);
}

FUNC_INLINE long
filter_addr_op_mod(__u32 op, long value)
{
    switch (op) {
    case op_filter_saddr:
    case op_filter_daddr:
        return !!value;         // DAddr: 地址在集合中则匹配
    case op_filter_notsaddr:
    case op_filter_notdaddr:
        return !value;          // NotDAddr: 地址不在集合中则匹配
    }
}
```

#### 2.2.2 端口匹配：Hash Map

端口匹配使用 `filter_32ty_map()`，通过 Hash Map 进行 O(1) 查找：

```c
// filter_32ty_map: 在 argfilter_maps 中查找值
FUNC_INLINE long
filter_32ty_map(struct selector_arg_filter *filter, char *args)
{
    __u32 map_idx = *(__u32 *)&filter->value;
    void *argmap = map_lookup_elem(&argfilter_maps, &map_idx);
    if (!argmap)
        return 0;
    return !!map_lookup_elem(argmap, args);
}
```

#### 2.2.3 协议/Family/State 匹配

同样使用 `filter_32ty_map()`，将协议号/地址族/TCP状态作为 key 在 Hash Map 中查找。

### 2.3 TrackSock 机制

TrackSock 是 Tetragon 的 Socket 生命周期跟踪机制，用于关联 Socket 创建者（PID/TID）与后续的连接/监听事件。

**完整工作流程**：

```
1. sk_alloc() 返回时:
   ┌──────────────────────────────────────────────────┐
   │ returnArgAction: TrackSock                        │
   │   → socktrack_map[sock_kernel_addr] = {pid, tid, ktime} │
   └──────────────────────────────────────────────────┘

2. tcp_connect() / inet_csk_listen_start() 触发时:
   ┌──────────────────────────────────────────────────┐
   │ copy_sock() 读取 sock 信息后:                      │
   │   → update_pid_tid_from_sock(e, sock_addr)        │
   │   → 从 socktrack_map 查找 sock_kernel_addr        │
   │   → 如果找到，更新事件的 pid/tid 为 Socket 创建者    │
   └──────────────────────────────────────────────────┘

3. __sk_free() / sk_free() 触发时:
   ┌─────────────────────────────────────────────────���┐
   │ matchActions: UntrackSock                         │
   │   → map_delete_elem(&socktrack_map, &sock_addr)   │
   └──────────────────────────────────────────────────┘
```

**BPF 数据结构**: `bpf/process/generic_calls.h` 中的 retprobe 处理

```c
// TrackSock: 在 sk_alloc 返回时记录 socket 所有者
case ACTION_TRACKSOCK:
    owner.pid = e->current.pid;
    owner.tid = e->tid;
    owner.ktime = e->current.ktime;
    map_update_elem(&socktrack_map, &ret, &owner, BPF_ANY);
    break;

// UntrackSock: 在 sk_free 时清理
case ACTION_UNTRACKSOCK:
    map_delete_elem(&socktrack_map, &ret);
    break;
```

**update_pid_tid_from_sock**: 当处理 sock 类型参数时，自动从 socktrack_map 查找关联的创建者信息，确保事件中的 PID 是 Socket 的真正创建者，而非当前执行 connect 的线程。

### 2.4 Socket 选择器编译

**Go 侧选择器操作符编译**: `pkg/selectors/kernel.go`

Go 侧将 YAML 中的网络操作符映射为 BPF 操作符：

| YAML 操作符 | Go 常量 | BPF 枚举 | 含义 |
|------------|---------|---------|------|
| `SAddr` | `SelectorOpSaddr` | `op_filter_saddr (13)` | 源地址匹配 |
| `DAddr` | `SelectorOpDaddr` | `op_filter_daddr (14)` | 目标地址匹配 |
| `SPort` | `SelectorOpSport` | `op_filter_sport (15)` | 源端口匹配 |
| `DPort` | `SelectorOpDport` | `op_filter_dport (16)` | 目标端口匹配 |
| `Protocol` | `SelectorOpProtocol` | `op_filter_protocol (17)` | 协议匹配 |
| `NotSPort` | `SelectorOpNotsport` | `op_filter_notsport (18)` | 源端口不匹配 |
| `NotDPort` | `SelectorOpNotdport` | `op_filter_notdport (19)` | 目标端口不匹配 |
| `SPortPriv` | `SelectorOpSportpriv` | `op_filter_sportpriv (20)` | 源端口 < 1024 |
| `DPortPriv` | `SelectorOpDportpriv` | `op_filter_dportpriv (22)` | 目标端口 < 1024 |
| `NotSAddr` | `SelectorOpNotsaddr` | `op_filter_notsaddr (24)` | 源地址不匹配 |
| `NotDAddr` | `SelectorOpNotdaddr` | `op_filter_notdaddr (25)` | 目标地址不匹配 |
| `Family` | `SelectorOpFamily` | `op_filter_family (28)` | 地址族匹配 |
| `State` | `SelectorOpState` | `op_filter_state (29)` | TCP 状态匹配 |

**Family 值映射** (Go 侧使用字符串，编译为整数):

```
"AF_INET"  → 2
"AF_INET6" → 10
```

**Protocol 值映射**:

```
"IPPROTO_TCP"  → 6
"IPPROTO_UDP"  → 17
"IPPROTO_ICMP" → 1
```

---

## 第三部分：Go 应用层源码分析

### 3.1 Socket 事件解析

**源码位置**: `pkg/sensors/tracing/args_linux.go`

当 `handleGenericKprobe` 解析到 `sock_type` 参数时，调用 `GenericSockType` 解析逻辑：

```
handleGenericKprobe():
    │
    ├─ 参数类型为 gt.GenericSockType:
    │     读取 sk_type 结构体（固定大小）
    │     解析 family, type, protocol
    │     解析 saddr/daddr（根据 family 选择 IPv4 或 IPv6）
    │     解析 sport, dport
    │     解析 state, sockaddr(内核地址)
    │     → 构建 MsgGenericKprobeArgSock
    │
    ├─ 参数类型为 gt.GenericSockaddrType:
    │     读取 sockaddr_in_type 结构体
    │     解析 sin_family, sin_port, sin_addr
    │     → 构建 MsgGenericKprobeArgSockaddr
    │
    └─ 参数类型为 gt.GenericSocketType:
          同 sock_type 处理（通过 socket→sock 间接引用）
```

### 3.2 Protobuf 输出

**源码位置**: `pkg/grpc/tracing/tracing.go`

Socket 类型参数最终转换为 `tetragon.KprobeArgSock` Protobuf 消息：

```protobuf
message KprobeArgSock {
    string family = 1;      // "AF_INET" / "AF_INET6"
    string type = 2;        // "SOCK_STREAM" / "SOCK_DGRAM"
    string protocol = 3;    // "IPPROTO_TCP" / "IPPROTO_UDP"
    string saddr = 4;       // "10.0.0.5" / "::1"
    string daddr = 5;       // "1.2.3.4"
    uint32 sport = 6;       // 54321
    uint32 dport = 7;       // 4444
    // ...
}
```

**JSON 输出示例**（tcp_connect 事件）：

```json
{
  "process_kprobe": {
    "process": {
      "binary": "/usr/bin/bash",
      "arguments": "-i",
      "pid": {"value": 12345}
    },
    "parent": {
      "binary": "/usr/sbin/nginx"
    },
    "function_name": "tcp_connect",
    "args": [{
      "sock_arg": {
        "family": "AF_INET",
        "type": "SOCK_STREAM",
        "protocol": "IPPROTO_TCP",
        "saddr": "10.0.0.5",
        "daddr": "203.0.113.50",
        "sport": 54321,
        "dport": 4444
      }
    }],
    "action": "KPROBE_ACTION_POST"
  }
}
```

### 3.3 完整数据流图

```
                    目标进程调用 connect()
                           │
                           ▼
              ┌─────────────────────────┐
              │  tcp_connect() 内核函数   │
              │  参数: struct sock *sk   │
              └────────────┬────────────┘
                           │ Kprobe 触发
                           ▼
              ┌─────────────────────────┐
              │  generic_kprobe_event() │
              │  (bpf_generic_kprobe.c) │
              └────────────┬────────────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    ▼                      ▼                      ▼
TAIL_CALL_FILTER    TAIL_CALL_SETUP    TAIL_CALL_PROCESS
  PID/NS 过滤        提取 pt_regs 参数    读取 sock 参数
  matchBinaries      a0 = sock 地址       set_event_from_sock()
                                          提取五元组
    │                      │                      │
    └──────────────────────┼──────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  TAIL_CALL_ARGS          │
              │  filter_inet()          │
              │  ├─ op_filter_notdaddr  │
              │  │  → filter_addr_map() │
              │  │  → LPM Trie 查询     │
              │  ├─ op_filter_dport     │
              │  │  → filter_32ty_map() │
              │  └─ op_filter_protocol  │
              │     → filter_32ty_map() │
              └────────────┬────────────┘
                           │ 匹配成功
                           ▼
              ┌─────────────────────────┐
              │  TAIL_CALL_ACTIONS       │
              │  ├─ ACTION_POST         │
              │  └─ ACTION_SIGKILL      │
              │     (���果配置了)          │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─���───────────────────────┐
              │  TAIL_CALL_SEND          │
              │  generic_output()       │
              │  → Ring Buffer 写入     │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  Go: handleGenericKprobe │
              │  解析 sk_type           │
              │  → family, protocol     │
              │  → saddr, daddr         │
              │  → sport, dport         │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  gRPC / JSON 输出        │
              │  process_kprobe {       │
              │    function: tcp_connect │
              │    args: [sock_arg]     │
              │    action: POST/SIGKILL │
              │  }                      │
              └─────────────────────────┘
```

---

## 第四部分：实战场景与策略

### 4.1 检测外连非内网 IP

**场景**: 监控所有进程的 TCP 外连行为，排除私有地址段和 Loopback。

**策略文件**: 基于 `examples/tracingpolicy/tcp-connect-only-private-addrs.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-reverse-shell-outbound"
spec:
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
        - "169.254.0.0/16"   # Link-local
        - "::1/128"          # IPv6 loopback
        - "fe80::/10"        # IPv6 link-local
        - "fc00::/7"         # IPv6 unique-local
      matchActions:
      - action: Post
```

**事件观察**:

```bash
# 观察所有外连非私有地址的 TCP 连接
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "tcp_connect")
  | {
      time: .time,
      binary: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      parent: .process_kprobe.parent.binary,
      daddr: .process_kprobe.args[0].sock_arg.daddr,
      dport: .process_kprobe.args[0].sock_arg.dport
    }'
```

### 4.2 检测可疑端口监听

**场景**: 检测进程在可疑端口（4444, 8888, 1337, 31337, 9001 等）上启动 TCP 监听。

**策略文件**: 基于 `examples/tracingpolicy/tcp-listen.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-bind-shell"
spec:
  kprobes:
  # 1. 跟踪 Socket 创建（TrackSock）
  - call: "sk_alloc"
    syscall: false
    return: true
    args:
    - index: 1
      type: int
      label: "family"
    returnArg:
      index: 0
      type: "sock"
    returnArgAction: "TrackSock"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "2"     # AF_INET
        - "10"    # AF_INET6
      matchActions:
      - action: "NoPost"   # 创建时不发送事件

  # 2. 跟踪 Socket 释放（UntrackSock）
  - call: "__sk_free"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Family"
        values:
        - "2"
        - "10"
      matchActions:
      - action: "UntrackSock"
        argSock: 0
      - action: "NoPost"

  # 3. 检测可疑端口监听
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
        - "6666"
```

**事件观察**:

```bash
# 检测可疑端口监听
tetra getevents -o json | jq '
  select(.process_kprobe.function_name == "inet_csk_listen_start")
  | {
      binary: .process_kprobe.process.binary,
      pid: .process_kprobe.process.pid.value,
      sport: .process_kprobe.args[0].sock_arg.sport,
      family: .process_kprobe.args[0].sock_arg.family
    }'
```

### 4.3 security_socket_connect LSM Hook

**场景**: 使用 LSM Hook `security_socket_connect` 实现全协议（TCP+UDP+更多）的连接监控，支持 Override 阻断。

**策略文件**: 基于 `examples/tracingpolicy/security-socket-connect.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-reverse-shell-all-protocols"
spec:
  kprobes:
  - call: "security_socket_connect"
    syscall: false
    args:
    - index: 0
      type: "socket"      # struct socket*，包含协议信息
    - index: 1
      type: "sockaddr"    # 连接目标地址
    - index: 2
      type: "int"         # 地址长度
    selectors:
    # 选择器 1: 监控所有 TCP/UDP 连接到外网地址
    - matchArgs:
      - index: 0
        operator: "Protocol"
        values:
        - "IPPROTO_TCP"
        - "IPPROTO_UDP"
      - index: 1
        operator: "Family"
        values:
        - "AF_INET"
        - "AF_INET6"
      - index: 1
        operator: "NotSAddr"     # sockaddr 中使用 SAddr 表示目标地址
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
```

**与 tcp_connect 的区别**:

| 特性 | `tcp_connect` | `security_socket_connect` |
|------|--------------|--------------------------|
| 参数类型 | `sock` (struct sock*) | `socket` + `sockaddr` |
| 协议覆盖 | 仅 TCP | 全协议 (TCP/UDP/RAW/...) |
| Override 支持 | 否（函数已执行） | 是（LSM 可阻断） |
| 地址信息来源 | sock 内部字段 | sockaddr 参数 |
| 操作符 | DAddr/SAddr/DPort/... | SAddr/SPort/Family（对 sockaddr） |
| 性能开销 | 低（仅 TCP） | 较高（所有 connect 调用） |

### 4.4 检测加密反弹 Shell

**场景**: 检测 `openssl` 或 `socat` 建立的加密反弹 Shell 连接。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-encrypted-reverse-shell"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # 匹配 openssl/socat 的外连行为
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/openssl"
        - "/usr/bin/socat"
        - "/usr/local/bin/socat"
        - "/usr/bin/ncat"         # ncat 支持 --ssl
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
```

**局限性**: 加密反弹 Shell 的流量内容无法在内核层解密检查。检测策略只能基于元数据（进程名、目标地址、端口）。对于真正隐蔽的加密反弹 Shell，需要结合：
- 进程执行维度（Doc 1）检测 openssl/socat 的启动参数
- FD 重定向维度（Doc 3）检测 dup2 行为
- 网络层 IDS 检测 TLS 握手特征

### 4.5 连接级 Enforcement

**场景**: 检测到外连可疑地址时直接杀死进程。

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "enforce-no-reverse-shell"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # 可疑外连 + 可疑进程 → Sigkill
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
      matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
      matchActions:
      - action: Sigkill
```

**Enforcement 模式控制**:

Tetragon 支持 Monitor 和 Enforce 两种模式。在 Monitor 模式下，`Sigkill`/`Override`/`NotifyEnforcer` 仅记录，不实际执行（参见 Doc 0 §2.4.5）。可通过 `spec.options` 或 Policy 级别的配置控制模式。

---

## 第五部分：绕过分析与对策

### 5.1 绕过技术

| 绕过技术 | 原理 | 能否绕过 tcp_connect | 能否绕过 security_socket_connect |
|---------|------|:---:|:---:|
| **UDP 反弹 Shell** | 使用 UDP 替代 TCP | ✅ 绕过 | ❌ 可检测 |
| **ICMP 隧道** | 通过 ICMP 封装数据 | ✅ 绕过 | ❌ 可检测（RAW socket） |
| **DNS 隧道** | 通过 DNS 查询/响应传输数据 | ✅ 绕过 | ❌ 部分可检测 |
| **HTTP 回调** | 通过 HTTP POST 外传数据 | ❌ 仍需 TCP 连接 | ❌ 可检测 |
| **代理转发** | 通过已有代理连接 | ❌ 代理进程发起连接 | ❌ 代理进程可见 |
| **IPv6** | 使用 IPv6 地址 | ❌ sock 包含 IPv6 信息 | ❌ 可检测 |
| **进程名伪装** | 重命名二进制文件 | ❌ 无关（按连接检测） | ❌ 无关 |
| **端口复用** | 使用 80/443 等常用端口 | ❌ 但可能绕过端口过滤 | ❌ 同左 |
| **SO_REUSEPORT** | 复用已有服务端口 | ❌ 新连接仍可见 | ❌ 可检测 |

### 5.2 对策

#### 5.2.1 UDP 反弹 Shell 检测

使用 `security_socket_connect` 替代 `tcp_connect` 可覆盖 UDP：

```yaml
# 或者使用专门的 UDP 监控策略
# 参见 examples/tracingpolicy/datagram.yaml
```

`security_socket_connect` 是 LSM Hook，在 `connect()` 系统调用的安全检查点触发，覆盖所有协议族和 Socket 类型。

#### 5.2.2 全协议覆盖

```yaml
# 监控所有协议的外连
- call: "security_socket_connect"
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
```

#### 5.2.3 联合进程维度

单独的网络监控可能产生误报（合法服务也会连接外网）。通过联合进程维度可以提高检测精度：

```yaml
# 网络连接 + 可疑进程
selectors:
- matchBinaries:
  - operator: "In"
    values:
    - "/usr/bin/bash"
    - "/usr/bin/python3"
    - "/usr/bin/nc"
  matchArgs:
  - index: 0
    operator: "NotDAddr"
    values:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
```

#### 5.2.4 端口复用应对

当攻击者使用 80/443 等常用端口时，仅靠端口过滤无法检测。应对策略：

1. **按进程过滤**: Shell/解释器连接 80/443 本身就是可疑行为
2. **按进程树过滤**: Web 服务器子进程不应发起外连（结合 matchParentBinaries，详见 Doc 1��
3. **联合 FD 重定向维度**: 即使使用常用端口，dup2(socket, 0/1/2) 仍然是强信号（详见 Doc 3）

### 5.3 性能考量

| Hook 点 | 触发频率 | 性能影响 | 建议 |
|---------|---------|---------|------|
| `tcp_connect` | 每次 TCP 连接 | 低 | 推荐默认使用 |
| `tcp_close` | 每次 TCP 关闭 | 低 | 需要生命周期时使用 |
| `tcp_sendmsg` | 每次 TCP 发送 | 中-高 | 谨慎使用，配合 RateLimit |
| `inet_csk_listen_start` | 每次 listen() | 低 | 推荐使用 |
| `security_socket_connect` | 每次 connect() | 中 | 全协议需求时使用 |
| `sk_alloc` + `__sk_free` | 每次 socket 创建/销毁 | 中 | TrackSock 需要时使用 |

**性能优化建议**:
- 优先使用 `matchBinaries` 缩小监控范围
- 使用 `NoPost` 动作避免不必要的事件输出
- 对高频 Hook 点使用 `RateLimit` 限速
- 使用 `NotDAddr` 排除已知安全地址段，减少事件量
