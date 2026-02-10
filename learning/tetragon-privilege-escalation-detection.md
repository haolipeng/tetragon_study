# Tetragon 提权检测全流程深度分析

## 目录

- [第一部分：架构概览与核心概念](#第一部分架构概览与核心概念)
- [第二部分：eBPF 内核层深度分析](#第二部分ebpf-内核层深度分析)
- [第三部分：Go 应用层深度分析](#第三部分go-应用层深度分析)
- [第四部分：完整数据流和时序图](#第四部分完整数据流和时序图)
- [第五部分：实战场景演示](#第五部分实战场景演示)
- [附录：关键数据结构完整定义](#附录关键数据结构完整定义)

---

## 第一部分：架构概览与核心概念

### 1.1 Tetragon 提权检测架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                        用户/管理员                                    │
│                    TracingPolicy YAML                                │
└────────────────────┬────────────────────────────────────────────────┘
                     │ kubectl apply
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Tetragon Operator/Agent                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Go 应用层                                                     │  │
│  │  ├─ Policy Parser (pkg/k8s/apis/cilium.io/v1alpha1/)        │  │
│  │  ├─ Selector Compiler (pkg/selectors/kernel.go)             │  │
│  │  ├─ BPF Loader (pkg/sensors/load_linux.go)                  │  │
│  │  └─ Event Processor (pkg/observer/observer_linux.go)        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                     │                           ▲                    │
│                     │ BPF syscalls              │ Ring/Perf Buffer   │
│                     ▼                           │                    │
└─────────────────────────────────────────────────────────────────────┘
                      │                           │
┌─────────────────────────────────────────────────────────────────────┐
│                      Linux Kernel                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  eBPF 内核层                                                   │  │
│  │  ├─ Hook Points                                               │  │
│  │  │  ├─ kprobe: security_bprm_committing_creds                │  │
│  │  │  ├─ kprobe: __sys_setuid/__sys_setgid/...                 │  │
│  │  │  ├─ kprobe: security_capset/cap_capable                   │  │
│  │  │  └─ LSM: generic_lsm_*                                     │  │
│  │  ├─ Detection Logic (bpf/process/bpf_execve_bprm_commit_creds.c)│
│  │  ├─ Tail Call Pipeline (setup→process→filter→actions→output) │  │
│  │  └─ BPF Maps (execve_map, tg_execve_joined_info_map, etc.)  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                          │
│  ┌────────────────────────▼──────────────────────────────────────┐ │
│  │  内核数据结构                                                   │ │
│  │  ├─ struct linux_binprm (bprm->cred, bprm->per_clear)        │ │
│  │  ├─ struct task_struct (task->cred, capabilities)            │ │
│  │  └─ struct cred (uid/gid/euid/egid, cap_permitted/effective) │ │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                      │
                      ▼
            进程执行/系统调用
```

### 1.2 提权检测覆盖场景

| 场景类型 | 检测方法 | Hook点 | 关键文件 |
|---------|---------|--------|---------|
| **Setuid/Setgid 执行** | 比较 euid vs uid, egid vs gid | `security_bprm_committing_creds` | `bpf_execve_bprm_commit_creds.c` |
| **文件 Capabilities** | 比较新旧 cap_permitted | `security_bprm_committing_creds` | `bpf_execve_bprm_commit_creds.c` |
| **系统调用提权** | 监控 setuid/setgid/setreuid 等 | `__sys_setuid`, `__sys_setgid`, 等 | `generic_kprobe` 框架 |
| **Capabilities 操作** | 监控 capset/cap_capable | `security_capset`, `cap_capable` | `generic_kprobe` 框架 |
| **User Namespace 创建** | 检测非特权进程创建 userns | `create_user_ns` | `generic_kprobe` 框架 |
| **容器逃逸相关** | 检测特权操作、挂载等 | 多个 LSM hooks | `generic_lsm_core.c` |

### 1.3 核心数据结构

#### eBPF 侧

```c
// 能力信息 (bpf/lib/bpf_cred.h)
struct msg_capabilities {
    union {
        struct {
            __u64 permitted;    // CAP_* 位图
            __u64 effective;    // CAP_* 位图
            __u64 inheritable;  // CAP_* 位图
        };
        __u64 c[3];  // 数组访问
    };
};

// 完整凭证信息 (bpf/lib/bpf_cred.h)
struct msg_cred {
    __u32 uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
    __u32 securebits;
    struct msg_capabilities caps;
    struct msg_user_namespace user_ns;
} __attribute__((packed));

// 执行标志 (bpf/lib/bpf_cred.h)
#define EXEC_SETUID       0x01  // setuid 执行
#define EXEC_SETGID       0x02  // setgid 执行
#define EXEC_FILE_CAPS    0x04  // 文件能力提权
#define EXEC_SETUID_ROOT  0x08  // setuid to root
#define EXEC_SETGID_ROOT  0x10  // setgid to root
```

#### Go 侧

```go
// Protobuf 定义 (api/v1/tetragon/capabilities.proto)
type CapabilitiesType int32
const (
    CAP_CHOWN           CapabilitiesType = 0
    CAP_SETUID          CapabilitiesType = 7
    CAP_NET_ADMIN       CapabilitiesType = 12
    CAP_SYS_ADMIN       CapabilitiesType = 21
    // ... 40+ capabilities
)

type Capabilities struct {
    Permitted   []CapabilitiesType
    Effective   []CapabilitiesType
    Inheritable []CapabilitiesType
}

// TracingPolicy 选择器 (pkg/k8s/apis/cilium.io/v1alpha1/types.go)
type CapabilitiesSelector struct {
    Type                  string   // "Effective"|"Permitted"|"Inheritable"
    Operator              string   // "In"|"NotIn"
    IsNamespaceCapability bool
    Values                []string // ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]
}
```

---

## 第二部分：eBPF 内核层深度分析

### 2.1 Setuid/Setgid 提权检测

#### 2.1.1 Hook 点选择原理

**为什么选择 `security_bprm_committing_creds`？**

```
execve() 系统调用执行流程：
  do_execve()
    ↓
  do_execveat_common()
    ↓
  bprm_execve()
    ↓
  exec_binprm()
    ↓
  search_binary_handler()
    ↓
  load_elf_binary()  (或其他格式加载器)
    ↓
  begin_new_exec()
    ↓
  bprm_creds_from_file()  ← 读取文件 setuid/setgid 位和 capabilities
    ├─ cap_bprm_creds_from_file()  ← LSM capability 模块处理
    └─ 设置 bprm->per_clear (personality flags to clear)
    ↓
  security_bprm_committing_creds(bprm)  ← Tetragon Hook 点
    ↓
  install_exec_creds(bprm)  ← 实际应用新凭证
```

**关键优势：**
1. 在凭证应用前捕获，可以读取新旧凭证
2. `bprm->per_clear` 标志已设置，可判断是否为特权执行
3. 时机最佳：既不太早（信息不全）也不太晚（凭证已生效）

#### 2.1.2 核心检测逻辑

**文件：** `bpf/process/bpf_execve_bprm_commit_creds.c`

```c
__attribute__((section("kprobe/security_bprm_committing_creds"), used))
void BPF_KPROBE(tg_kp_bprm_committing_creds, struct linux_binprm *bprm)
{
    struct execve_map_value *curr;
    struct execve_heap *heap;
    struct task_struct *task;
    __u32 pid, ruid, euid, uid, egid, gid, sec = 0;
    __u64 permitted, new_permitted, new_ambient = 0;

    // 步骤1: 获取当前进程的 execve_map 条目
    tid = get_current_pid_tgid();
    pid = (tid >> 32);
    curr = execve_map_get_noinit(pid);
    if (!curr) return;

    // 步骤2: 获取 per-CPU 堆内存
    heap = map_lookup_elem(&execve_heap, &zero);
    if (!heap) return;
    memset(&heap->info, 0, sizeof(struct execve_info));

    // 步骤3: 读取 bprm->per_clear，检查是否为特权执行
    if (BPF_CORE_READ_INTO(&sec, bprm, per_clear) != 0 || sec == 0)
        goto out;  // 非特权执行，跳过

    // 步骤4: 检测 setuid
    euid = BPF_CORE_READ(bprm, cred, euid.val);  // 新的 effective uid
    task = (struct task_struct *)get_current_task();
    uid = BPF_CORE_READ(task, cred, uid.val);    // 当前的 real uid

    if (euid != uid) {
        heap->info.secureexec |= EXEC_SETUID;

        // 检查是否提权到 root
        ruid = BPF_CORE_READ(bprm, cred, uid.val);
        if (!__is_uid_global_root(ruid) && __is_uid_global_root(euid))
            heap->info.secureexec |= EXEC_SETUID_ROOT;
    }

    // 步骤5: 检测 setgid（逻辑类似）
    egid = BPF_CORE_READ(bprm, cred, egid.val);
    gid = BPF_CORE_READ(task, cred, gid.val);
    if (egid != gid) {
        heap->info.secureexec |= EXEC_SETGID;
        // 检查是否提权到 root group...
    }

    // 步骤6: 检测文件 capabilities
    BPF_CORE_READ_INTO(&new_ambient, bprm, cred, cap_ambient);
    if (new_ambient) goto out;  // ambient caps 与 file caps 互斥

    BPF_CORE_READ_INTO(&permitted, task, cred, cap_permitted);
    BPF_CORE_READ_INTO(&new_permitted, bprm, cred, cap_permitted);

    if (__cap_gained(new_permitted, permitted) && euid == uid) {
        // 获得新能力且 uid 未变 → 文件 capabilities
        heap->info.secureexec |= EXEC_FILE_CAPS;
    }

out:
    // 步骤7: 缓存到 LRU map（用于 execve 事件读取）
    if (heap->info.secureexec != 0 ||
        (heap->info.i_nlink == 0 && heap->info.i_ino != 0))
        execve_joined_info_map_set(tid, &heap->info);
}
```

**关键宏和辅助函数：**

```c
// bpf/lib/bpf_cred.h

// 检查能力是否为子集
FUNC_INLINE bool __cap_issubset(const __u64 a, const __u64 set) {
    return !(a & ~set);  // a 的所有位都在 set 中
}

// 检测是否获得新能力（target 中有 source 没有的位）
#define __cap_gained(target, source) !__cap_issubset(target, source)

// 检查是否为全局 root (uid == 0)
FUNC_INLINE bool __is_uid_global_root(__u32 uid) {
    return uid == 0;
}
```

#### 2.1.3 数据流和 Map 交互

```
security_bprm_committing_creds Hook
    ↓
读取 execve_map[pid] → execve_map_value
    ↓
读取 execve_heap[0] → execve_heap (per-CPU)
    ↓
检测逻辑 (比较 uid/gid/capabilities)
    ↓
设置 heap->info.secureexec 标志
    ↓
写入 tg_execve_joined_info_map[tid] → execve_info
    ↓
后续 execve event 读取该 map，获取提权标志
```

**关键 BPF Maps：**

```c
// bpf/lib/process.h

// Per-CPU 堆内存
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct execve_heap);
} execve_heap SEC(".maps");

// 跨 hook 点共享信息
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);  // tid
    __type(value, struct execve_info);
} tg_execve_joined_info_map SEC(".maps");

// 主进程映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);  // pid
    __type(value, struct execve_map_value);
} execve_map SEC(".maps");
```

### 2.2 系统调用提权检测（通用 Kprobe 框架）

#### 2.2.1 Tail Call 架构设计

**文件：** `bpf/process/bpf_generic_kprobe.c`

Tetragon 使用 tail call 将复杂的 kprobe 处理逻辑分解为多个阶段：

```c
// bpf/process/types/basic.h
enum {
    TAIL_CALL_SETUP = 0,       // 初始化事件结构
    TAIL_CALL_PROCESS = 1,     // 处理函数参数
    TAIL_CALL_FILTER = 2,      // 应用选择器过滤
    TAIL_CALL_ARGS = 3,        // 高级参数处理
    TAIL_CALL_ACTIONS = 4,     // 执行动作 (sigkill/override)
    TAIL_CALL_SEND = 5,        // 发送事件到用户态
    TAIL_CALL_PATH = 6,        // 路径解析
    TAIL_CALL_PROCESS_2 = 7,   // 第二阶段处理
    TAIL_CALL_ARGS_2 = 8,      // 第二阶段参数
};

// Tail call map
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 13);
    __type(key, __u32);
    __type(value, __u32);
} kprobe_calls SEC(".maps");
```

**为什么需要 Tail Call？**

1. **指令数限制：** Linux 4.x 内核限制单个 BPF 程序 4096 条指令
2. **模块化：** 每个阶段独立开发和测试
3. **条件跳过：** 根据过滤结果跳过不必要的阶段
4. **代码重用：** 多个 kprobe 共享相同的处理逻辑

**执行流程示例（监控 __sys_setuid）：**

```
generic_kprobe_event() [入口]
    ├─ 初始化 msg_generic_kprobe 结构
    ├─ 读取当前进程 capabilities (get_current_subj_caps)
    ├─ 读取 namespaces (get_namespaces)
    └─ tail_call(TAIL_CALL_FILTER) ──────────┐
                                              │
generic_kprobe_process_filter()  ←───────────┘
    ├─ 检查 PID/namespace/capability 过滤器
    ├─ if (不匹配) return
    └─ tail_call(TAIL_CALL_SETUP) ───────────┐
                                             │
generic_kprobe_setup_event()  ←──────────────┘
    ├─ 设置事件元数据
    └─ tail_call(TAIL_CALL_PROCESS) ─────────┐
                                             │
generic_kprobe_process_event()  ←────────────┘
    ├─ 读取函数参数 (PT_REGS_PARM1, PARM2, ...)
    ├─ 参数类型转换 (int/string/file/capability)
    └─ tail_call(TAIL_CALL_FILTER) ──────────┐
                                             │
generic_kprobe_filter_arg()  ←───────────────┘
    ├─ 参数值过滤 (matchArgs)
    ├─ Capability 变更过滤 (CapabilitiesGained)
    └─ tail_call(TAIL_CALL_ACTIONS) ─────────┐
                                             │
generic_kprobe_actions()  ←──────────────────┘
    ├─ 执行动作 (sigkill/override)
    └─ tail_call(TAIL_CALL_SEND) ────────────┐
                                             │
generic_kprobe_output()  ←───────────────────┘
    └─ 发送事件到 ring buffer
```

#### 2.2.2 Capabilities 信息获取

**文件：** `bpf/process/bpf_process_event.h`

```c
// 从 cred 结构体读取 capabilities
FUNC_INLINE void __get_caps(struct msg_capabilities *msg,
                             const struct cred *cred)
{
    probe_read(&msg->effective, sizeof(__u64),
               _(&cred->cap_effective));
    probe_read(&msg->inheritable, sizeof(__u64),
               _(&cred->cap_inheritable));
    probe_read(&msg->permitted, sizeof(__u64),
               _(&cred->cap_permitted));
}

// 获取当前任务的主观 capabilities
FUNC_INLINE void get_current_subj_caps(struct msg_capabilities *msg,
                                        struct task_struct *task)
{
    const struct cred *cred;

    // 读取主观凭证指针 (task->cred)
    probe_read(&cred, sizeof(cred), _(&task->cred));
    __get_caps(msg, cred);
}

// 获取完整凭证信息 (uid/gid + capabilities)
FUNC_INLINE void get_current_subj_creds(struct msg_cred *info,
                                         struct task_struct *task)
{
    const struct cred *cred;

    probe_read(&cred, sizeof(cred), _(&task->cred));

    // 读取所有 uid/gid 字段
    probe_read(&info->uid, sizeof(__u32), _(&cred->uid));
    probe_read(&info->gid, sizeof(__u32), _(&cred->gid));
    probe_read(&info->euid, sizeof(__u32), _(&cred->euid));
    probe_read(&info->egid, sizeof(__u32), _(&cred->egid));
    probe_read(&info->suid, sizeof(__u32), _(&cred->suid));
    probe_read(&info->sgid, sizeof(__u32), _(&cred->sgid));
    probe_read(&info->fsuid, sizeof(__u32), _(&cred->fsuid));
    probe_read(&info->fsgid, sizeof(__u32), _(&cred->fsgid));
    probe_read(&info->securebits, sizeof(__u32), _(&cred->securebits));

    // 读取 capabilities
    __get_caps(&info->caps, cred);
}
```

**CO-RE (Compile Once, Run Everywhere) 的使用：**

```c
// _(P) 宏启用 CO-RE 字段重定位
#define _(P) (__builtin_preserve_access_index(P))

// 链式读取
__u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

// 等价于：
struct task_struct *parent;
__u32 ppid;
bpf_core_read(&parent, sizeof(parent), &task->real_parent);
bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
```

### 2.3 Capability 变更检测 (CapabilitiesGained)

#### 2.3.1 操作符实现

**文件：** `bpf/process/bpf_generic_kprobe.c` (filter_arg 阶段)

```c
// 伪代码逻辑（简化）
case SelectorOpCapabilitiesGained:
    // 读取新旧 capabilities
    __u64 old_caps = saved_capabilities;  // 从之前保存的值
    __u64 new_caps = current_capabilities; // 当前进程的值

    // 检测新增的 capabilities
    __u64 gained = new_caps & ~old_caps;

    // 匹配选择器指定的 capabilities
    __u64 target_caps = selector_values;  // 从 BPF map 读取

    if (gained & target_caps) {
        // 匹配！进程获得了我们关注的 capabilities
        matched = true;
    }
    break;
```

#### 2.3.2 TracingPolicy 示例

```yaml
# 检测进程获得 CAP_SYS_ADMIN 或 CAP_NET_ADMIN
selectors:
  - matchCapabilityChanges:
      - type: Effective
        operator: In
        values:
          - "CAP_SYS_ADMIN"
          - "CAP_NET_ADMIN"
```

**编译过程：**
1. YAML 解析 → `CapabilitiesSelector` 结构体
2. 能力名称 → 枚举值：`CAP_SYS_ADMIN` = 21, `CAP_NET_ADMIN` = 12
3. 生成位图：`(1 << 21) | (1 << 12)` = `0x0000000000101000`
4. 写入 BPF selector map
5. BPF 程序读取并应用过滤

### 2.4 性能优化技巧

#### 2.4.1 Per-CPU Array 避免栈溢出

BPF 栈大小限制为 512 字节，使用 per-CPU array 作为"堆"：

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct large_struct);  // 可以很大
} heap SEC(".maps");

SEC("kprobe/xxx")
int my_kprobe(void *ctx) {
    __u32 zero = 0;
    struct large_struct *data = bpf_map_lookup_elem(&heap, &zero);
    // 使用 data->... 而不是栈变量
}
```

**优势：**
- 每个 CPU 独立，无竞争
- 不占用栈空间
- 查找开销低（固定索引 0）

#### 2.4.2 减少 Map 查找次数

```c
// ❌ 不好：多次查找
val1 = bpf_map_lookup_elem(&map, &key);
// ... 中间代码 ...
val2 = bpf_map_lookup_elem(&map, &key);  // 重复查找！

// ✅ 好：缓存结果
val = bpf_map_lookup_elem(&map, &key);
if (val) {
    // 使用 val 多次
}
```

**Tetragon 案例：** `execve_map_get_noinit()` 在函数开始时查找一次，后续复用。

#### 2.4.3 提前返回（Early Return）

```c
// ✅ 尽早检查过滤条件
if (filter_not_matched)
    return 0;  // 避免后续复杂计算

// 继续处理...
```

**Tetragon 案例：** `bpf_execve_bprm_commit_creds.c:81` 检查 `per_clear == 0` 后立即返回。

---

## 第三部分：Go 应用层深度分析

### 3.1 BPF 程序加载流程

#### 3.1.1 核心文件和函数

**文件：** `pkg/sensors/load_linux.go`

```go
// 加载 BPF map
func loadMap(m *program.Map, load *program.Program) error {
    // 步骤1: 检查是否已加载（引用计数）
    if m.IsLoaded() {
        m.IncrementUsage()
        return nil
    }

    // 步骤2: 加载 CollectionSpec
    spec, err := bpf.LoadCollectionSpec(load.PinPath)
    if err != nil {
        return err
    }

    // 步骤3: 复制 mapSpec（避免修改原始规范）
    mapSpec := spec.Maps[m.Name].Copy()

    // 步骤4: 设置 Pin Path
    m.SetPinPath(filepath.Join(bpf.MapPrefixPath(),
                               load.Type, load.Name, m.Name))

    // 步骤5: 配置最大条目数
    if m.MaxEntries > 0 {
        mapSpec.MaxEntries = m.MaxEntries
    }

    // 步骤6: 加载或创建 pinned map
    bpfMap, err := bpf.LoadOrCreatePinnedMap(mapSpec, m.PinPath)
    if err != nil {
        return err
    }

    m.SetMap(bpfMap)
    m.IncrementUsage()
    return nil
}

// 加载 BPF 程序
func observerLoadInstance(spec *program.LoadOpts,
                          prog *program.Program) error {
    // 获取内核版本
    kernelVersion, err := kernels.GetKernelVersion()
    if err != nil {
        return err
    }

    // 根据程序类型加载
    switch spec.Type {
    case "tracepoint":
        return loadTracepointProgram(spec, prog, kernelVersion)
    case "raw_tracepoint":
        return loadRawTracepointProgram(spec, prog, kernelVersion)
    case "kprobe", "kretprobe":
        return loadKprobeProgram(spec, prog, kernelVersion)
    case "lsm":
        return loadLSMProgram(spec, prog, kernelVersion)
    // ...
    }

    return nil
}
```

#### 3.1.2 Map 类型和用途

| Map 类型 | 用途 | 示例 |
|---------|------|------|
| `MapTypeGlobal` | 全局共享 | `events` (ring buffer) |
| `MapTypePolicy` | 策略级配置 | `argfilter_maps`, `string_maps` |
| `MapTypeSensor` | 传感器级 | `execve_map`, `process_call_heap` |
| `MapTypeProgram` | 程序级 Tail Call | `kprobe_calls`, `lsm_calls` |

### 3.2 事件读取和解析

#### 3.2.1 Ring/Perf Buffer 读取

**文件：** `pkg/observer/observer_linux.go`

```go
func (k *Observer) RunEvents(ctx context.Context, config *Config) error {
    // 步骤1: 加载 perf buffer map
    perfMap, err := ebpf.LoadPinnedMap(
        filepath.Join(bpf.MapPrefixPath(), config.MapName),
        &ebpf.LoadPinOptions{})
    if err != nil {
        return err
    }

    // 步骤2: 创建 perf reader
    perfReader, err := perf.NewReader(perfMap, config.BufferSize)
    if err != nil {
        return err
    }

    // 步骤3: 创建事件队列
    eventsQueue := make(chan *perf.Record, config.QueueSize)

    // 步骤4: 启动读取 goroutine
    go func() {
        for {
            record, err := perfReader.Read()
            if err != nil {
                if errors.Is(err, perf.ErrClosed) {
                    return
                }
                continue
            }
            eventsQueue <- &record
        }
    }()

    // 步骤5: 处理事件 goroutine
    go func() {
        for record := range eventsQueue {
            k.receiveEvent(record.RawSample)
        }
    }()

    // 步骤6: 如果内核 >= 5.11，同时启动 ring buffer 读取
    if kernelVersion >= kernel511 {
        go k.readRingBuffer(ctx)
    }

    <-ctx.Done()
    return nil
}
```

#### 3.2.2 事件分发机制

**文件：** `pkg/observer/observer.go`

```go
// 全局事件处理器映射
var eventHandler = map[uint8]func(*bytes.Reader) ([]Event, error){}

func RegisterEventHandlerAtInit(op uint8,
                                 handler func(*bytes.Reader) ([]Event, error)) {
    eventHandler[op] = handler
}

func (k *Observer) receiveEvent(data []byte) {
    // 步骤1: 提取 opcode (事件类型)
    opcode := data[0]

    // 步骤2: 查找对应的处理器
    handler, ok := eventHandler[opcode]
    if !ok {
        logger.Warn("Unknown event type", "opcode", opcode)
        return
    }

    // 步骤3: 调用处理器解析事件
    reader := bytes.NewReader(data)
    events, err := handler(reader)
    if err != nil {
        logger.Error("Failed to handle event", err)
        return
    }

    // 步骤4: 通知所有监听器
    for _, ev := range events {
        k.notifyListeners(ev)
    }
}
```

**事件处理器注册示例：**

```go
// pkg/sensors/tracing/generickprobe.go:58-64
func init() {
    sensors.RegisterProbeType("generic_kprobe", &observerKprobeSensor{})
    observer.RegisterEventHandlerAtInit(
        ops.MSG_OP_GENERIC_KPROBE,  // opcode
        handleGenericKprobe,         // 处理函数
    )
}
```

### 3.3 Capability 信息转换

#### 3.3.1 BPF → Go 数据转换

**文件：** `pkg/reader/caps/caps.go`

```go
// 将 BPF 侧的 MsgCapabilities 转换为 Protobuf 格式
func GetMsgCapabilities(caps processapi.MsgCapabilities) *tetragon.Capabilities {
    return &tetragon.Capabilities{
        Permitted:   GetCapabilitiesTypes(caps.Permitted),
        Effective:   GetCapabilitiesTypes(caps.Effective),
        Inheritable: GetCapabilitiesTypes(caps.Inheritable),
    }
}

// 将 uint64 位图转换为 []CapabilitiesType
func GetCapabilitiesTypes(capInt uint64) []tetragon.CapabilitiesType {
    var caps []tetragon.CapabilitiesType

    // 遍历 64 位
    for i := range uint64(64) {
        if (1 << i) & capInt != 0 {
            caps = append(caps, tetragon.CapabilitiesType(i))
        }
    }

    return caps
}
```

**转换示例：**

```
BPF:   0x0000000000201080  (bits 7, 12, 21 set)
       ↓
Parse: bit 7  → CAP_SETUID       (CapabilitiesType = 7)
       bit 12 → CAP_NET_ADMIN    (CapabilitiesType = 12)
       bit 21 → CAP_SYS_ADMIN    (CapabilitiesType = 21)
       ↓
Proto: []CapabilitiesType{7, 12, 21}
```

### 3.4 规则引擎与选择器

#### 3.4.1 TracingPolicy 解析

**文件：** `pkg/k8s/apis/cilium.io/v1alpha1/types.go`

```go
// TracingPolicy 结构体
type TracingPolicy struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata"`
    Spec              TracingPolicySpec `json:"spec"`
}

type TracingPolicySpec struct {
    KProbes     []KProbeSpec     `json:"kprobes,omitempty"`
    Tracepoints []TracepointSpec `json:"tracepoints,omitempty"`
    LSM         []LSMSpec        `json:"lsm,omitempty"`
}

type KProbeSpec struct {
    Call      string            `json:"call"`
    Syscall   bool              `json:"syscall"`
    Return    bool              `json:"return"`
    Args      []KProbeArg       `json:"args"`
    Selectors []KProbeSelector  `json:"selectors"`
    Message   string            `json:"message,omitempty"`
    Tags      []string          `json:"tags,omitempty"`
}

type KProbeSelector struct {
    MatchPIDs              []PIDSelector              `json:"matchPIDs,omitempty"`
    MatchArgs              []ArgSelector              `json:"matchArgs,omitempty"`
    MatchCapabilities      []CapabilitiesSelector     `json:"matchCapabilities,omitempty"`
    MatchCapabilityChanges []CapabilitiesSelector     `json:"matchCapabilityChanges,omitempty"`
    MatchNamespaces        []NamespaceSelector        `json:"matchNamespaces,omitempty"`
    MatchActions           []ActionSelector           `json:"matchActions,omitempty"`
    MatchBinaries          []BinarySelector           `json:"matchBinaries,omitempty"`
}

type CapabilitiesSelector struct {
    Type                  string   `json:"type"`     // "Effective"|"Permitted"|"Inheritable"
    Operator              string   `json:"operator"` // "In"|"NotIn"
    IsNamespaceCapability bool     `json:"isNamespaceCapability"`
    Values                []string `json:"values"`   // ["CAP_SYS_ADMIN", ...]
}
```

#### 3.4.2 选择器编译为 BPF Maps

**文件：** `pkg/selectors/kernel.go`

```go
// 将 capability 名称转换为 uint64 位图
func capsStrToUint64(values []string) (uint64, error) {
    caps := uint64(0)

    for _, v := range values {
        // 查找 capability 枚举值
        c, ok := tetragon.CapabilitiesType_value[valstr]
        if !ok {
            return 0, fmt.Errorf("unknown capability: %s", v)
        }

        // 设置对应的位
        caps |= (1 << c)
    }

    return caps, nil
}

// 示例
// Input:  ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"]
// Lookup: CAP_SYS_ADMIN = 21, CAP_NET_ADMIN = 12
// Output: (1 << 21) | (1 << 12) = 0x0000000000101000
```

**写入 BPF Map 流程：**

```go
func writeCapabilitySelectorToMap(selector CapabilitiesSelector,
                                   mapFd int) error {
    // 步骤1: 解析 capability 类型
    capType := capabilitiesTypeTable[selector.Type]  // 0=permitted, 1=effective, 2=inheritable

    // 步骤2: 将 capability 名称转为位图
    capBitmap, err := capsStrToUint64(selector.Values)
    if err != nil {
        return err
    }

    // 步骤3: 构造 selector 数据
    data := struct {
        Op                    uint32
        Type                  uint32
        IsNamespaceCapability uint8
        Value                 uint64
    }{
        Op:                    SelectorOpCapabilitiesGained,
        Type:                  capType,
        IsNamespaceCapability: boolToUint8(selector.IsNamespaceCapability),
        Value:                 capBitmap,
    }

    // 步骤4: 写入 BPF map
    key := selectorIndex
    err = bpf.UpdateElem(mapFd, unsafe.Pointer(&key),
                         unsafe.Pointer(&data), 0)
    return err
}
```

### 3.5 事件上报（gRPC Server）

#### 3.5.1 gRPC 服务实现

**文件：** `pkg/server/server.go`

```go
type Server struct {
    notifier Notifier
    observer Observer
}

func (s *Server) GetEventsWG(request *tetragon.GetEventsRequest,
                              server tetragon.FineGuidanceSensors_GetEventsServer) error {
    // 步骤1: 解析过滤器
    allowList := buildAllowList(request.AllowList)
    denyList := buildDenyList(request.DenyList)

    // 步骤2: 创建监听器
    listener := newListener(allowList, denyList)

    // 步骤3: 注册到 notifier
    s.notifier.AddListener(listener)
    defer s.notifier.RemoveListener(listener)

    // 步骤4: 监听事件并发送
    for {
        select {
        case event := <-listener.events:
            // 应用过滤器
            if !filters.Apply(allowList, denyList, event) {
                continue
            }

            // 应用字段过滤器
            for _, filter := range request.FieldFilters {
                event = filter.Filter(event)
            }

            // 发送给客户端
            if err := server.Send(&tetragon.GetEventsResponse{
                Event: event,
            }); err != nil {
                return err
            }

        case <-server.Context().Done():
            return nil
        }
    }
}
```

#### 3.5.2 Capability 过滤器

**Protobuf 定义：** `api/v1/tetragon/events.proto`

```protobuf
message CapFilter {
    CapFilterSet permitted = 1;
    CapFilterSet effective = 2;
    CapFilterSet inheritable = 3;
}

message CapFilterSet {
    repeated CapabilitiesType any = 1;  // 至少有其中一个
    repeated CapabilitiesType all = 2;  // 必须全部拥有
    repeated CapabilitiesType exactly = 3;  // 精确匹配
    repeated CapabilitiesType none = 4;  // 都不能有
}
```

**过滤逻辑：**

```go
func applyCapabilityFilter(event ProcessKprobe,
                            filter CapFilter) bool {
    // 检查 effective capabilities
    if filter.Effective != nil {
        if !matchCapFilterSet(event.Process.Caps.Effective,
                               filter.Effective) {
            return false
        }
    }

    // 检查 permitted capabilities
    if filter.Permitted != nil {
        if !matchCapFilterSet(event.Process.Caps.Permitted,
                               filter.Permitted) {
            return false
        }
    }

    return true
}

func matchCapFilterSet(caps []CapabilitiesType,
                        filter CapFilterSet) bool {
    // Any: 至少有一个
    if len(filter.Any) > 0 {
        if !hasAny(caps, filter.Any) {
            return false
        }
    }

    // All: 必须全部拥有
    if len(filter.All) > 0 {
        if !hasAll(caps, filter.All) {
            return false
        }
    }

    // None: 都不能有
    if len(filter.None) > 0 {
        if hasAny(caps, filter.None) {
            return false
        }
    }

    return true
}
```

---

## 第四部分：完整数据流和时序图

### 4.1 Setuid 执行检测完整流程

```
时间轴
  │
  │  用户空间                  内核空间
  │  ─────────                ───────────
  │
  │  1. kubectl apply -f privileges-setuid-root.yaml
  │     └─ Tetragon Agent 接收 TracingPolicy
  │        ├─ 解析 YAML → KProbeSpec
  │        ├─ 编译 selectors → BPF maps
  │        └─ 加载 BPF 程序 (bpf_execve_bprm_commit_creds.c)
  │
  ├─────────────────────────────────────────────────────
  │
  │  2. 恶意用户执行: ./suid_binary
  │                                    │
  │                                    ▼
  │                          3. execve("/path/to/suid_binary")
  │                                    │
  │                                    ├─ do_execve()
  │                                    ├─ load_elf_binary()
  │                                    ├─ bprm_creds_from_file()
  │                                    │  ├─ 读取文件 setuid 位
  │                                    │  ├─ 设置 bprm->cred->euid = 0
  │                                    │  └─ 设置 bprm->per_clear 标志
  │                                    │
  │                                    ▼
  │                          4. security_bprm_committing_creds(bprm)
  │                                    │
  │                                    ▼ [Kprobe Hook]
  │                          5. BPF: tg_kp_bprm_committing_creds()
  │                                    ├─ 读取 bprm->per_clear (非0)
  │                                    ├─ 比较 euid(0) vs uid(1000)
  │                                    │  → 检测到 EXEC_SETUID
  │                                    ├─ euid == 0 && uid != 0
  │                                    │  → 设置 EXEC_SETUID_ROOT
  │                                    ├─ 写入 execve_info 到 LRU map
  │                                    └─ 返回
  │                                    │
  │                                    ▼
  │                          6. install_exec_creds(bprm)
  │                                    └─ 应用新凭证（euid=0）
  │
  ├─────────────────────────────────────────────────────
  │
  │  7. Tracepoint: sched_process_exec
  │                                    │
  │                                    ▼ [Tracepoint Hook]
  │                          8. BPF: event_execve()
  │                                    ├─ 查找 LRU map[tid]
  │                                    │  → 获取 execve_info
  │                                    ├─ 读取进程信息
  │                                    ├─ 构造 msg_execve_event
  │                                    │  ├─ pid, uid, binary path
  │                                    │  └─ flags: EXEC_SETUID_ROOT
  │                                    └─ 写入 ring buffer
  │
  ├─────────────────────────────────────────────────────
  │
  │  9. Tetragon Agent: RunEvents()
  │     ├─ 从 ring buffer 读取
  │     ├─ receiveEvent(data)
  │     │  ├─ opcode = MSG_OP_EXECVE
  │     │  ├─ handler = handleExecve()
  │     │  └─ 解析二进制数据
  │     │
  │     ├─ 10. 转换数据格式
  │     │     ├─ flags → ProcessPrivilegesChanged
  │     │     └─ 构造 ProcessExec Protobuf
  │     │
  │     └─ 11. notifyListeners(event)
  │            └─ gRPC Server
  │
  ├─────────────────────────────────────────────────────
  │
  │  12. gRPC Client (tetra, Falco, etc.)
  │      └─ 接收 GetEventsResponse
  │         └─ ProcessExec {
  │              process: { pid, binary, ... }
  │              parent: { ... }
  │              flags: PRIVILEGES_RAISED_EXEC_FILE_SETUID
  │            }
  │
  ▼
```

### 4.2 系统调用提权检测流程（__sys_setuid）

```
时间轴
  │
  │  1. TracingPolicy: privileges-raise.yaml
  │     └─ kprobe: __sys_setuid(uid=0)
  │
  ├─────────────────────────────────────────────────────
  │
  │  2. 恶意进程调用: setuid(0)
  │                                    │
  │                                    ▼
  │                          3. __sys_setuid(0)
  │                                    │
  │                                    ▼ [Kprobe Hook]
  │                          4. BPF: generic_kprobe_event()
  │                                    ├─ 读取当前 capabilities
  │                                    │  get_current_subj_caps()
  │                                    ├─ 读取 namespaces
  │                                    └─ tail_call(TAIL_CALL_FILTER)
  │                                           │
  │                                           ▼
  │                          5. BPF: generic_kprobe_process_filter()
  │                                    ├─ 检查 PID 过滤
  │                                    ├─ 检查 namespace 过滤
  │                                    ├─ 检查 capability 过滤
  │                                    │  (是否有 CAP_SETUID?)
  │                                    └─ tail_call(TAIL_CALL_SETUP)
  │                                           │
  │                                           ▼
  │                          6. BPF: generic_kprobe_setup_event()
  │                                    ├─ 初始化 msg_generic_kprobe
  │                                    └─ tail_call(TAIL_CALL_PROCESS)
  │                                           │
  │                                           ▼
  │                          7. BPF: generic_kprobe_process_event()
  │                                    ├─ 读取参数: uid = 0
  │                                    │  PT_REGS_PARM1(ctx)
  │                                    └─ tail_call(TAIL_CALL_FILTER)
  │                                           │
  │                                           ▼
  │                          8. BPF: generic_kprobe_filter_arg()
  │                                    ├─ matchArgs:
  │                                    │  index=0, operator=Equal, value=0
  │                                    │  → 匹配！
  │                                    └─ tail_call(TAIL_CALL_ACTIONS)
  │                                           │
  │                                           ▼
  │                          9. BPF: generic_kprobe_actions()
  │                                    ├─ action: Post
  │                                    ├─ rateLimit: 1m
  │                                    └─ tail_call(TAIL_CALL_SEND)
  │                                           │
  │                                           ▼
  │                          10. BPF: generic_kprobe_output()
  │                                     ├─ 构造完整事件
  │                                     │  ├─ 进程信息
  │                                     │  ├─ 函数名: __sys_setuid
  │                                     │  ├─ 参数: uid=0
  │                                     │  └─ capabilities
  │                                     └─ 写入 ring buffer
  │
  ├─────────────────────────────────────────────────────
  │
  │  11. Tetragon Agent: handleGenericKprobe()
  │      ├─ 从 ring buffer 读取
  │      ├─ 解析参数
  │      │  ├─ arg[0] type=int → value=0
  │      │  └─ 类型转换
  │      ├─ 查找 genericKprobeTable
  │      │  └─ 获取 policy name, message, tags
  │      └─ 构造 ProcessKprobe Protobuf
  │
  │  12. gRPC 发送给客户端
  │      └─ ProcessKprobe {
  │           function_name: "__sys_setuid"
  │           args: [{ int_arg: 0 }]
  │           policy_name: "privileges-raise"
  │           message: "Privileged operation setuid to root"
  │         }
  │
  ▼
```

### 4.3 Capability 变更检测流程（matchCapabilityChanges）

```
时间轴
  │
  │  1. TracingPolicy: 监控 create_user_ns
  │     └─ matchCapabilityChanges:
  │        - type: Effective
  │          operator: In
  │          values: ["CAP_SYS_ADMIN"]
  │
  ├─────────────────────────────────────────────────────
  │
  │  2. 编译 selector → BPF map
  │     ├─ capsStrToUint64(["CAP_SYS_ADMIN"])
  │     │  → 0x0000000000200000 (bit 21)
  │     ├─ 写入 selector map:
  │     │  {
  │     │    op: SelectorOpCapabilitiesGained,
  │     │    type: capsEffective,
  │     │    value: 0x0000000000200000
  │     │  }
  │     └─ 加载 BPF 程序
  │
  ├─────────────────────────────────────────────────────
  │
  │  3. 非特权进程执行: unshare -Ur
  │                                    │
  │                                    ▼
  │                          4. unshare(CLONE_NEWUSER)
  │                                    │
  │                                    ├─ copy_creds()
  │                                    │  └─ 保存旧 capabilities
  │                                    │
  │                                    ▼
  │                          5. create_user_ns()
  │                                    │ [Kprobe Hook - Entry]
  │                                    ▼
  │                          6. BPF: generic_kprobe_event()
  │                                    ├─ 读取旧 capabilities:
  │                                    │  caps_old = 0x0000000000000000
  │                                    │  (无 CAP_SYS_ADMIN)
  │                                    └─ 保存到 per-CPU map
  │
  │                          7. create_user_ns() 执行
  │                                    ├─ 创建新 user namespace
  │                                    └─ 在新 ns 中授予全能力
  │
  │                                    │ [Kretprobe Hook - Return]
  │                                    ▼
  │                          8. BPF: generic_kprobe_event() [return]
  │                                    ├─ 读取新 capabilities:
  │                                    │  caps_new = 0x000003FFFFFFFFFF
  │                                    │  (包含 CAP_SYS_ADMIN)
  │                                    │
  │                                    ├─ 9. filter_arg 阶段
  │                                    │  ├─ 计算 gained:
  │                                    │  │  gained = caps_new & ~caps_old
  │                                    │  │        = 0x000003FFFFFFFFFF
  │                                    │  │
  │                                    │  ├─ 读取 selector:
  │                                    │  │  target = 0x0000000000200000
  │                                    │  │
  │                                    │  ├─ 检查匹配:
  │                                    │  │  if (gained & target)
  │                                    │  │  → 0x200000 匹配！
  │                                    │  │
  │                                    │  └─ 继续到 actions
  │                                    │
  │                                    └─ 10. 发送事件到 ring buffer
  │
  ├─────────────────────────────────────────────────────
  │
  │  11. Tetragon Agent 接收事件
  │      ├─ 解析 capability 变更
  │      │  ├─ old: []
  │      │  └─ new: [CAP_SYS_ADMIN, CAP_NET_ADMIN, ...]
  │      └─ 构造 ProcessKprobe 事件
  │
  │  12. 发送给客户端
  │      └─ 告警：进程获得了 CAP_SYS_ADMIN
  │
  ▼
```

---

## 第五部分：实战场景演示

### 5.1 场景1：检测 Setuid Root 执行

#### 环境准备

```bash
# 1. 创建 setuid root 测试程序
cat > test_setuid.c << 'EOF'
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Real UID: %d\n", getuid());
    printf("Effective UID: %d\n", geteuid());
    return 0;
}
EOF

gcc -o test_setuid test_setuid.c
sudo chown root:root test_setuid
sudo chmod u+s test_setuid  # 设置 setuid 位

# 验证
ls -l test_setuid
# -rwsr-xr-x 1 root root ...
```

#### 触发检测

```bash
# 作为普通用户执行
./test_setuid
```

#### 预期事件输出

```json
{
  "process_exec": {
    "process": {
      "exec_id": "...",
      "pid": 12345,
      "uid": 1000,
      "cwd": "/home/user",
      "binary": "/home/user/test_setuid",
      "arguments": "",
      "flags": "execve",
      "cap": {
        "permitted": ["CAP_CHOWN", "CAP_KILL", "..."],
        "effective": ["CAP_CHOWN", "CAP_KILL", "..."],
        "inheritable": []
      },
      "process_credentials": {
        "uid": 1000,
        "gid": 1000,
        "euid": 0,
        "egid": 1000,
        "suid": 0,
        "sgid": 1000,
        "fsuid": 0,
        "fsgid": 1000
      },
      "binary_properties": {
        "setuid": 2,
        "privileges_changed": [
          "PRIVILEGES_RAISED_EXEC_FILE_SETUID"
        ]
      }
    },
    "parent": {"...": "..."}
  }
}
```

**关键字段：**
- `euid: 0` 且 `uid: 1000` → setuid 执行
- `privileges_changed: ["PRIVILEGES_RAISED_EXEC_FILE_SETUID"]` → 标记提权
- `cap.effective` 包含所有能力 → root 权限

### 5.2 场景2：检测系统调用提权（setuid(0)）

#### TracingPolicy 配置

```yaml
# sys-setuid-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-sys-setuid-root"
spec:
  kprobes:
  - call: "__sys_setuid"
    syscall: false
    message: "Process attempting setuid to root"
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "0"
      matchActions:
      - action: Post
```

#### 测试程序

```c
// test_syscall_setuid.c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("Before: uid=%d, euid=%d\n", getuid(), geteuid());

    // 尝试提权（如果有 CAP_SETUID 则成功）
    if (setuid(0) == 0) {
        printf("After: uid=%d, euid=%d\n", getuid(), geteuid());
        printf("Successfully escalated to root!\n");
    } else {
        perror("setuid failed");
    }

    return 0;
}
```

```bash
gcc -o test_syscall_setuid test_syscall_setuid.c

# 赋予 CAP_SETUID（容器场景）
sudo setcap cap_setuid+ep test_syscall_setuid

./test_syscall_setuid
```

#### 预期事件输出

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "...",
      "pid": 23456,
      "uid": 1000,
      "binary": "/home/user/test_syscall_setuid",
      "cap": {
        "permitted": ["CAP_SETUID"],
        "effective": ["CAP_SETUID"],
        "inheritable": []
      }
    },
    "function_name": "__sys_setuid",
    "args": [
      {
        "int_arg": 0
      }
    ],
    "action": "KPROBE_ACTION_POST",
    "policy_name": "detect-sys-setuid-root",
    "message": "Process attempting setuid to root"
  }
}
```

### 5.3 场景3：检测 Capability 变更

#### TracingPolicy 配置

```yaml
# capability-change-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-cap-sys-admin-gain"
spec:
  kprobes:
  - call: "commit_creds"
    syscall: false
    message: "Process gained CAP_SYS_ADMIN"
    args:
    - index: 0
      type: "cred"
    selectors:
    - matchCapabilityChanges:
      - type: Effective
        operator: In
        values:
        - "CAP_SYS_ADMIN"
      matchActions:
      - action: Post
```

#### 测试：创建 User Namespace

```bash
# 普通用户执行
unshare -Ur /bin/bash

# 在新 namespace 中，进程获得完整 capabilities
capsh --print
```

#### 预期事件输出

```json
{
  "process_kprobe": {
    "process": {
      "pid": 34567,
      "uid": 1000,
      "binary": "/usr/bin/unshare",
      "cap": {
        "permitted": [
          "CAP_CHOWN", "CAP_KILL", "CAP_SETUID",
          "CAP_SYS_ADMIN", "..."
        ],
        "effective": [
          "CAP_CHOWN", "CAP_KILL", "CAP_SETUID",
          "CAP_SYS_ADMIN", "..."
        ]
      },
      "ns": {
        "user": {
          "level": 1,
          "uid": 0,
          "gid": 0
        }
      }
    },
    "function_name": "commit_creds",
    "policy_name": "detect-cap-sys-admin-gain",
    "message": "Process gained CAP_SYS_ADMIN"
  }
}
```

### 5.4 场景4：检测容器逃逸（特权容器）

#### TracingPolicy 配置

```yaml
# container-escape-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-privileged-mount"
spec:
  kprobes:
  - call: "security_sb_mount"
    syscall: false
    message: "Privileged mount operation detected"
    args:
    - index: 0
      type: "string"  # dev_name
    - index: 1
      type: "path"    # mountpoint
    - index: 2
      type: "string"  # fs_type
    selectors:
    - matchCapabilities:
      - type: Effective
        operator: In
        values:
        - "CAP_SYS_ADMIN"
      matchArgs:
      - index: 2
        operator: "In"
        values:
        - "devtmpfs"
        - "proc"
        - "sysfs"
      matchActions:
      - action: Post
```

#### 测试：特权容器挂载宿主机

```bash
# 启动特权容器
docker run --rm -it --privileged ubuntu:latest bash

# 在容器内挂载宿主机根文件系统
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# 验证
ls /mnt/host/root
```

#### 预期事件输出

```json
{
  "process_kprobe": {
    "process": {
      "pid": 45678,
      "uid": 0,
      "binary": "/bin/mount",
      "cap": {
        "effective": ["CAP_SYS_ADMIN", "..."]
      },
      "pod": {
        "namespace": "default",
        "name": "privileged-pod-xxx",
        "container": {
          "id": "docker://...",
          "name": "ubuntu",
          "image": {
            "name": "ubuntu:latest"
          },
          "privileged": true
        }
      }
    },
    "function_name": "security_sb_mount",
    "args": [
      { "string_arg": "/dev/sda1" },
      { "path_arg": "/mnt/host" },
      { "string_arg": "ext4" }
    ],
    "policy_name": "detect-privileged-mount",
    "message": "Privileged mount operation detected"
  }
}
```

---

## 附录：关键数据结构完整定义

### A.1 BPF 侧结构体

```c
// msg_capabilities (bpf/lib/bpf_cred.h)
struct msg_capabilities {
    union {
        struct {
            __u64 permitted;
            __u64 effective;
            __u64 inheritable;
        };
        __u64 c[3];
    };
};

// msg_cred (bpf/lib/bpf_cred.h)
struct msg_cred {
    __u32 uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
    __u32 securebits;
    __u32 pad;
    struct msg_capabilities caps;
    struct msg_user_namespace user_ns;
} __attribute__((packed));

// execve_info (bpf/lib/process.h)
struct execve_info {
    __u32 secureexec;  // EXEC_SETUID | EXEC_SETGID | ...
    __u32 i_nlink;
    __u64 i_ino;
};

// execve_map_value (bpf/lib/process.h)
struct execve_map_value {
    struct msg_execve_key key;
    __u32 flags;
    __u32 nspid;
    struct msg_capabilities caps;
    struct msg_ns ns;
    struct binary binary;
    // ...
};
```

### A.2 Protobuf 定义

```protobuf
// api/v1/tetragon/capabilities.proto
enum CapabilitiesType {
    CAP_CHOWN = 0;
    CAP_DAC_OVERRIDE = 1;
    CAP_DAC_READ_SEARCH = 2;
    CAP_FOWNER = 3;
    CAP_FSETID = 4;
    CAP_KILL = 5;
    CAP_SETGID = 6;
    CAP_SETUID = 7;
    CAP_SETPCAP = 8;
    CAP_LINUX_IMMUTABLE = 9;
    CAP_NET_BIND_SERVICE = 10;
    CAP_NET_BROADCAST = 11;
    CAP_NET_ADMIN = 12;
    CAP_NET_RAW = 13;
    CAP_IPC_LOCK = 14;
    CAP_IPC_OWNER = 15;
    CAP_SYS_MODULE = 16;
    CAP_SYS_RAWIO = 17;
    CAP_SYS_CHROOT = 18;
    CAP_SYS_PTRACE = 19;
    CAP_SYS_PACCT = 20;
    CAP_SYS_ADMIN = 21;
    CAP_SYS_BOOT = 22;
    CAP_SYS_NICE = 23;
    CAP_SYS_RESOURCE = 24;
    CAP_SYS_TIME = 25;
    CAP_SYS_TTY_CONFIG = 26;
    CAP_MKNOD = 27;
    CAP_LEASE = 28;
    CAP_AUDIT_WRITE = 29;
    CAP_AUDIT_CONTROL = 30;
    CAP_SETFCAP = 31;
    CAP_MAC_OVERRIDE = 32;
    CAP_MAC_ADMIN = 33;
    CAP_SYSLOG = 34;
    CAP_WAKE_ALARM = 35;
    CAP_BLOCK_SUSPEND = 36;
    CAP_AUDIT_READ = 37;
    CAP_PERFMON = 38;
    CAP_BPF = 39;
    CAP_CHECKPOINT_RESTORE = 40;
}

message Capabilities {
    repeated CapabilitiesType permitted = 1;
    repeated CapabilitiesType effective = 2;
    repeated CapabilitiesType inheritable = 3;
}

enum ProcessPrivilegesChanged {
    PRIVILEGES_RAISED_EXEC_FILE_CAP = 1;
    PRIVILEGES_RAISED_EXEC_FILE_SETUID = 2;
    PRIVILEGES_RAISED_EXEC_FILE_SETGID = 3;
}
```

---

**文档版本：** v1.0
**更新日期：** 2026-02-09
**适用 Tetragon 版本：** v1.2+
