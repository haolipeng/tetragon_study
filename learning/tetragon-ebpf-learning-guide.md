# Tetragon eBPF 内核态学习指南

## 目录
- [1. Tetragon eBPF 功能概览](#1-tetragon-ebpf-功能概览)
- [2. 学习路线图](#2-学习路线图)
- [3. Demo 实践系列](#3-demo-实践系列)
- [4. Git Commit 学习要点](#4-git-commit-学习要点)
- [5. eBPF 新特性应用](#5-ebpf-新特性应用)
- [6. 常见 Bug 和优化](#6-常见-bug-和优化)

---

## 1. Tetragon eBPF 功能概览

### 1.1 核心功能矩阵

| 功能模块 | 实现文件 | eBPF 技术 | 难度 |
|---------|---------|----------|------|
| 进程执行监控 | `bpf_execve_event.c` | Tracepoint | ⭐⭐ |
| 进程退出监控 | `bpf_exit.c` | Tracepoint | ⭐ |
| 进程创建监控 | `bpf_fork.c` | Tracepoint | ⭐⭐ |
| 内核函数监控 | `bpf_generic_kprobe.c` | Kprobe/Kretprobe | ⭐⭐⭐ |
| 用户态函数监控 | `bpf_generic_uprobe.c` | Uprobe/Uretprobe | ⭐⭐⭐ |
| 追踪点监控 | `bpf_generic_tracepoint.c` | Tracepoint | ⭐⭐ |
| 原始追踪点 | `bpf_generic_rawtp.c` | Raw Tracepoint | ⭐⭐⭐ |
| USDT 探针 | `bpf_generic_usdt.c` | USDT | ⭐⭐⭐⭐ |
| LSM 安全钩子 | `bpf_generic_lsm_*.c` | BPF LSM | ⭐⭐⭐⭐ |
| Cgroup 监控 | `bpf_cgroup_*.c` | Cgroup hooks | ⭐⭐⭐ |
| 策略执行 | `bpf_enforcer.c` | fmod_ret | ⭐⭐⭐⭐ |

### 1.2 关键 eBPF 技术栈

```
┌─────────────────────────────────────────────────────────────┐
│                    Tetragon eBPF 技术栈                      │
├─────────────────────────────────────────────────────────────┤
│  探针类型     │ kprobe, uprobe, tracepoint, LSM, fentry    │
├─────────────────────────────────────────────────────────────┤
│  Map 类型     │ HASH, ARRAY, PERCPU_ARRAY, PROG_ARRAY,     │
│               │ LPM_TRIE, RINGBUF, PERF_EVENT_ARRAY        │
├─────────────────────────────────────────────────────────────┤
│  高级特性     │ Tail Calls, CO-RE, BPF Iterators,          │
│               │ fmod_ret, sleepable BPF                    │
├─────────────────────────────────────────────────────────────┤
│  内核版本支持  │ 4.19, 5.3, 5.11, 6.1+                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 学习路线图

### 阶段一：eBPF 基础（1-2周）

```
Week 1-2: 基础概念
├── Day 1-2: BPF Map 类型和操作
├── Day 3-4: Tracepoint 基础
├── Day 5-7: Kprobe 基础
├── Day 8-10: 数据传递（perf buffer, ring buffer）
└── Day 11-14: CO-RE 和 BTF
```

### 阶段二：进阶技术（2-3周）

```
Week 3-5: 进阶特性
├── Tail Calls 链式调用
├── Uprobe 用户态探针
├── Raw Tracepoint
├── BPF Iterators
└── LSM 钩子
```

### 阶段三：Tetragon 实战（2-3周）

```
Week 6-8: 项目实战
├── 复现 execve 监控
├── 实现 kprobe 过滤器
├── 添加自定义策略
└── 性能优化实践
```

---

## 3. Demo 实践系列

### Demo 1: Hello World - 最简单的 eBPF 程序

**学习目标**: 理解 eBPF 程序结构、SEC 宏、license 声明

**对应 Tetragon 代码**: `bpf/process/bpf_loader.c`

```c
// demo1_hello.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx)
{
    bpf_printk("Hello, execve called!");
    return 0;
}
```

**编译和运行**:
```bash
# 编译
clang -O2 -g -target bpf -c demo1_hello.bpf.c -o demo1_hello.bpf.o

# 加载（需要 bpftool 或编写用户态程序）
sudo bpftool prog load demo1_hello.bpf.o /sys/fs/bpf/hello
sudo bpftool prog attach pinned /sys/fs/bpf/hello tracepoint:syscalls:sys_enter_execve

# 查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

### Demo 2: BPF Map 基础

**学习目标**: 理解 BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY

**对应 Tetragon 代码**: `bpf/process/bpf_execve_event.c:47-52`

```c
// demo2_maps.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// 1. Hash Map - 存储进程计数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // PID
    __type(value, __u64);    // 执行次数
} exec_count SEC(".maps");

// 2. Per-CPU Array - 临时数据存储（避免栈溢出）
struct event_data {
    __u32 pid;
    __u64 timestamp;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_data);
} data_heap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_execve(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count, init_val = 1;

    // 查找或初始化计数
    count = bpf_map_lookup_elem(&exec_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&exec_count, &pid, &init_val, BPF_ANY);
    }

    // 使用 per-cpu array 存储临时数据
    __u32 zero = 0;
    struct event_data *data = bpf_map_lookup_elem(&data_heap, &zero);
    if (data) {
        data->pid = pid;
        data->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(data->comm, sizeof(data->comm));
    }

    return 0;
}
```

**Tetragon 中的实际应用**:
- `execve_msg_heap_map`: 用于存储 execve 事件的临时数据
- `data_heap`: Per-CPU 数组，避免栈空间限制

---

### Demo 3: Tracepoint 详解 - execve 监控

**学习目标**: 理解 tracepoint 上下文、参数读取、数据结构

**对应 Tetragon 代码**: `bpf/process/bpf_execve_event.c:254-328`

```c
// demo3_execve.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 事件结构
struct execve_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

// Ring Buffer 用于传递事件到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tetragon 使用的 tracepoint 上下文结构
// 参考: trace_event_raw_sched_process_exec
SEC("tracepoint/sched/sched_process_exec")
int trace_execve(struct trace_event_raw_sched_process_exec *ctx)
{
    struct execve_event *event;
    struct task_struct *task;

    // 从 ring buffer 预留空间
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // 获取当前任务
    task = (struct task_struct *)bpf_get_current_task();

    // 填充事件数据
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // 读取父进程 PID (CO-RE 方式)
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // 读取文件名 - Tetragon 的方式
    // ctx->__data_loc_filename 包含偏移量和长度
    // 低 16 位是偏移量，高 16 位是长度
    unsigned short offset = ctx->__data_loc_filename & 0xFFFF;
    char *filename = (char *)ctx + offset;
    bpf_probe_read_str(event->filename, sizeof(event->filename), filename);

    // 提交事件
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

**关键点解析**:

1. **`__data_loc_filename`**: Tracepoint 使用动态定位的字符串
   - 低 16 位: 字符串在上下文中的偏移量
   - 高 16 位: 字符串长度
   - Tetragon 代码: `char *filename = (char *)ctx + (_(ctx->__data_loc_filename) & 0xFFFF);`

2. **CO-RE 读取**: 使用 `BPF_CORE_READ` 安全读取内核结构

---

### Demo 4: Tail Call 链式调用

**学习目标**: 理解 BPF_MAP_TYPE_PROG_ARRAY 和 bpf_tail_call

**对应 Tetragon 代码**: `bpf/process/bpf_execve_event.c:32-43`, `bpf/process/bpf_generic_kprobe.c:29-50`

```c
// demo4_tailcall.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// 声明 tail call 目标函数
int stage1_process(void *ctx);
int stage2_filter(void *ctx);
int stage3_output(void *ctx);

// Prog Array - 存储 tail call 目标
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __array(values, int(void *));  // 函数指针数组
} prog_array SEC(".maps") = {
    .values = {
        [0] = (void *)&stage1_process,
        [1] = (void *)&stage2_filter,
        [2] = (void *)&stage3_output,
    },
};

// 共享数据 - 通过 map 在 tail call 之间传递
struct shared_data {
    __u32 pid;
    __u32 stage;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shared_data);
} shared_heap SEC(".maps");

// 入口点
SEC("tracepoint/syscalls/sys_enter_execve")
int entry_point(void *ctx)
{
    __u32 zero = 0;
    struct shared_data *data = bpf_map_lookup_elem(&shared_heap, &zero);
    if (!data)
        return 0;

    // 初始化共享数据
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->stage = 0;
    data->timestamp = bpf_ktime_get_ns();

    // Tail call 到 stage1
    bpf_tail_call(ctx, &prog_array, 0);

    // 如果 tail call 失败，会执行到这里
    bpf_printk("Tail call to stage1 failed");
    return 0;
}

// Stage 1: 处理数据
SEC("tracepoint")
int stage1_process(void *ctx)
{
    __u32 zero = 0;
    struct shared_data *data = bpf_map_lookup_elem(&shared_heap, &zero);
    if (!data)
        return 0;

    data->stage = 1;
    bpf_printk("Stage 1: Processing PID %d", data->pid);

    // 继续到 stage2
    bpf_tail_call(ctx, &prog_array, 1);
    return 0;
}

// Stage 2: 过滤
SEC("tracepoint")
int stage2_filter(void *ctx)
{
    __u32 zero = 0;
    struct shared_data *data = bpf_map_lookup_elem(&shared_heap, &zero);
    if (!data)
        return 0;

    data->stage = 2;

    // 示例过滤: 只允许 PID > 1000
    if (data->pid <= 1000) {
        bpf_printk("Stage 2: Filtered out PID %d", data->pid);
        return 0;  // 不继续
    }

    // 继续到 stage3
    bpf_tail_call(ctx, &prog_array, 2);
    return 0;
}

// Stage 3: 输出
SEC("tracepoint")
int stage3_output(void *ctx)
{
    __u32 zero = 0;
    struct shared_data *data = bpf_map_lookup_elem(&shared_heap, &zero);
    if (!data)
        return 0;

    data->stage = 3;
    __u64 latency = bpf_ktime_get_ns() - data->timestamp;
    bpf_printk("Stage 3: Output PID %d, latency %llu ns", data->pid, latency);

    return 0;
}
```

**Tetragon Tail Call 设计**:

```
Tetragon kprobe 处理流程:
┌─────────────────┐
│  generic_kprobe │ (入口)
└────────┬────────┘
         │ tail_call
         ▼
┌─────────────────┐
│  setup_event    │ (设置事件)
└────────┬────────┘
         │ tail_call
         ▼
┌─────────────────┐
│  process_event  │ (处理参数)
└────────┬────────┘
         │ tail_call
         ▼
┌─────────────────┐
│  process_filter │ (策略过滤)
└────────┬────────┘
         │ tail_call
         ▼
┌─────────────────┐
│  filter_arg     │ (参数过滤)
└────────┬────────┘
         │ tail_call
         ▼
┌─────────────────┐
│  actions        │ (执行动作)
└────────┬────────┘
         │ tail_call
         ▼
┌─────────────────┐
│  output         │ (输出事件)
└─────────────────┘
```

**为什么需要 Tail Call?**
1. **绕过指令限制**: 4.19 内核限制 4096 条指令，通过 tail call 可以拆分
2. **模块化设计**: 每个阶段独立，便于维护
3. **条件执行**: 可以根据条件跳过某些阶段

---

### Demo 5: Kprobe 内核函数监控

**学习目标**: 理解 kprobe 挂载、pt_regs 参数读取、返回值处理

**对应 Tetragon 代码**: `bpf/process/bpf_generic_kprobe.c`

```c
// demo5_kprobe.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 事件结构
struct file_open_event {
    __u32 pid;
    __u32 ret;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 存储入口参数，供 kretprobe 使用
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);           // pid_tgid
    __type(value, char[256]);     // filename
} entry_args SEC(".maps");

// Kprobe: 监控 do_sys_openat2 入口
// 函数签名: int do_sys_openat2(int dfd, const char __user *filename,
//                              struct open_how *how)
SEC("kprobe/do_sys_openat2")
int kprobe_openat2(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // 读取第二个参数: filename (用户态指针)
    // x86_64: rdi=arg1, rsi=arg2, rdx=arg3...
    // ARM64: x0=arg1, x1=arg2, x2=arg3...
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    char buf[256] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    // 保存到 map，供 kretprobe 使用
    bpf_map_update_elem(&entry_args, &pid_tgid, buf, BPF_ANY);

    return 0;
}

// Kretprobe: 获取返回值
SEC("kretprobe/do_sys_openat2")
int kretprobe_openat2(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // 获取返回值
    int ret = PT_REGS_RC(ctx);

    // 查找入口时保存的参数
    char *filename = bpf_map_lookup_elem(&entry_args, &pid_tgid);
    if (!filename)
        return 0;

    // 准备事件
    struct file_open_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&entry_args, &pid_tgid);
        return 0;
    }

    event->pid = pid_tgid >> 32;
    event->ret = ret;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_probe_read_str(event->filename, sizeof(event->filename), filename);

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&entry_args, &pid_tgid);

    return 0;
}
```

**Tetragon 的 retprobe_map 设计**:

参考 `bpf/process/retprobe_map.h`:
- 使用 `retprobe_map` 存储入口参数
- Key 是 `pid_tgid + kprobe_id`
- 支持多个 kprobe 同时监控

---

### Demo 6: CO-RE (Compile Once, Run Everywhere)

**学习目标**: 理解 BTF、bpf_core_read、字段存在性检查

**对应 Tetragon 代码**: `bpf/lib/bpf_helpers.h:56`, `bpf/lib/bpf_task.h`

```c
// demo6_core.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// CO-RE 宏定义 (Tetragon 使用)
// _(P) 宏用于 CO-RE 字段访问
#define _(P) (__builtin_preserve_access_index(P))

// 检查字段是否存在
#define bpf_core_field_exists(field) \
    __builtin_preserve_field_info(field, BPF_FIELD_EXISTS)

SEC("tracepoint/sched/sched_process_exec")
int core_demo(void *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 方法1: 使用 BPF_CORE_READ 宏
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);

    // 方法2: 使用 bpf_core_read() 函数
    __u32 ppid;
    bpf_core_read(&ppid, sizeof(ppid), &task->real_parent->tgid);

    // 方法3: 链式读取
    // 读取 task->mm->arg_start
    unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);

    // 方法4: 检查字段是否存在 (处理内核版本差异)
    // 某些字段可能只在特定内核版本存在
    if (bpf_core_field_exists(task->loginuid)) {
        __u32 loginuid;
        bpf_core_read(&loginuid, sizeof(loginuid), &task->loginuid.val);
        bpf_printk("loginuid: %d", loginuid);
    }

    // 方法5: Tetragon 风格的读取
    // 使用 with_errmetrics 宏进行错误追踪
    struct mm_struct *mm = NULL;
    bpf_probe_read(&mm, sizeof(mm), _(&task->mm));
    if (mm) {
        unsigned long start_stack;
        bpf_probe_read(&start_stack, sizeof(start_stack), _(&mm->arg_start));
        bpf_printk("arg_start: %lx", start_stack);
    }

    bpf_printk("CO-RE: pid=%d, tgid=%d, ppid=%d", pid, tgid, ppid);
    return 0;
}
```

**CO-RE 关键概念**:

1. **BTF (BPF Type Format)**: 内核类型信息，允许 BPF 程序了解内核数据结构布局
2. **字段重定位**: 编译时不绑定具体偏移，加载时根据运行内核的 BTF 重定位
3. **`__builtin_preserve_access_index`**: 告诉编译器保留访问索引信息

---

### Demo 7: BPF Iterators (新特性)

**学习目标**: 理解 bpf_for、bpf_for_each、bpf_iter_num

**对应 Tetragon 代码**: `bpf/lib/bpf_helpers.h:121-216`

**Git Commit 参考**:
- `af2b494f9 tetragon: Add CONFIG_ITER_NUM bool`
- `f01224ed9 tetragon: Use CONFIG_ITER_NUM in prepend_path`

```c
// demo7_iterators.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// BPF Iterator 相关的 kfuncs 声明
extern void bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __ksym;

// bpf_for 宏 - Tetragon 的实现
#define bpf_for(i, start, end) for (                                           \
    struct bpf_iter_num ___it __attribute__((aligned(8),                       \
                                             cleanup(bpf_iter_num_destroy))),  \
    *___p __attribute__((unused)) = (                                          \
        bpf_iter_num_new(&___it, (start), (end)),                             \
        (void)bpf_iter_num_destroy, (void *)0);                                \
    ({                                                                         \
        int *___t = bpf_iter_num_next(&___it);                                \
        (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));               \
    });                                                                        \
)

SEC("tracepoint/syscalls/sys_enter_execve")
int iterator_demo(void *ctx)
{
    int i;
    __u64 sum = 0;

    // 使用 bpf_for 进行有界循环
    // 这比传统的 #pragma unroll 更灵活
    bpf_for(i, 0, 10) {
        sum += i;
        bpf_printk("i = %d, sum = %llu", i, sum);
    }

    bpf_printk("Final sum: %llu", sum);
    return 0;
}
```

**为什么需要 BPF Iterators?**

1. **传统方式的问题**:
   - BPF 验证器需要证明循环会终止
   - `#pragma unroll` 只能展开固定次数
   - 运行时确定的循环次数很难处理

2. **BPF Iterator 的优势**:
   - 验证器友好：明确的上下界
   - 支持运行时确定的循环次数
   - 自动资源清理（通过 cleanup 属性）

---

### Demo 8: fmod_ret - 函数返回值修改

**学习目标**: 理解 BPF_MODIFY_RETURN、override_return

**对应 Tetragon 代码**: `bpf/process/bpf_generic_kprobe.c:195-207`, `bpf/process/bpf_enforcer.c`

```c
// demo8_fmodret.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// 用于存储需要拦截的 PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // PID
    __type(value, __s32);   // 返回的错误码
} block_pids SEC(".maps");

// fmod_ret: 修改 security_file_open 的返回值
// 这可以阻止特定进程打开文件
SEC("fmod_ret/security_file_open")
int block_file_open(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __s32 *error = bpf_map_lookup_elem(&block_pids, &pid);
    if (!error)
        return 0;  // 不修改返回值

    // 返回错误码，阻止操作
    // 通常返回 -EPERM (-1) 或 -EACCES (-13)
    return *error;
}

// kprobe + override_return 方式 (旧方法)
// 需要 CONFIG_BPF_KPROBE_OVERRIDE=y
SEC("kprobe/__x64_sys_openat")
int override_openat(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __s32 *error = bpf_map_lookup_elem(&block_pids, &pid);
    if (!error)
        return 0;

    // 使用 bpf_override_return 修改返回值
    // 注意: 这需要内核配置支持
    bpf_override_return(ctx, *error);
    return 0;
}
```

**Tetragon 的策略执行**:

Tetragon 使用这种机制实现：
- **Sigkill**: 终止恶意进程
- **Override**: 修改系统调用返回值
- **GetURL/DnsLookup**: 阻止特定网络访问

---

### Demo 9: LSM 钩子 (Linux Security Module)

**学习目标**: 理解 BPF LSM 钩子、安全策略实现

**对应 Tetragon 代码**: `bpf/process/bpf_generic_lsm_core.c`

```c
// demo9_lsm.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 阻止的路径列表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[64]);    // 路径前缀
    __type(value, __u8);      // 1 = blocked
} blocked_paths SEC(".maps");

// LSM 钩子: file_open
// 在文件打开时进行安全检查
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    char path_buf[64] = {};
    struct path f_path;
    struct dentry *dentry;
    struct qstr d_name;

    // 读取文件路径
    bpf_core_read(&f_path, sizeof(f_path), &file->f_path);
    bpf_core_read(&dentry, sizeof(dentry), &f_path.dentry);
    bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name);

    bpf_probe_read_str(path_buf, sizeof(path_buf), d_name.name);

    // 检查是否在阻止列表中
    // 简化版本: 只检查文件名
    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path_buf);
    if (blocked && *blocked) {
        bpf_printk("LSM: Blocked access to %s", path_buf);
        return -1;  // -EPERM
    }

    return 0;
}

// LSM 钩子: bprm_check_security
// 在执行程序前进行检查
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    char filename[256] = {};

    bpf_probe_read_str(filename, sizeof(filename),
                       BPF_CORE_READ(bprm, filename));

    bpf_printk("LSM bprm_check: %s", filename);

    // 示例: 阻止执行 /tmp 目录下的程序
    if (filename[0] == '/' && filename[1] == 't' &&
        filename[2] == 'm' && filename[3] == 'p' && filename[4] == '/') {
        bpf_printk("LSM: Blocked execution from /tmp");
        return -1;
    }

    return 0;
}
```

**LSM vs Kprobe**:

| 特性 | LSM | Kprobe |
|------|-----|--------|
| 设计目的 | 安全策略 | 调试/跟踪 |
| 返回值语义 | 明确的允许/拒绝 | 观察性的 |
| 稳定性 | API 稳定 | 可能随内核变化 |
| 性能影响 | 针对安全优化 | 可能较高 |

---

### Demo 10: 完整的进程监控系统

**学习目标**: 综合运用以上技术构建完整系统

```c
// demo10_process_monitor.bpf.c
// 这是一个综合 Demo，模拟 Tetragon 的核心功能

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ========== 数据结构定义 ==========

struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 ktime;
    char comm[16];
    char filename[256];
    char args[256];
};

struct filter_config {
    __u32 uid_filter;      // 只监控特定 UID
    __u8 filter_enabled;
};

// ========== BPF Maps ==========

// Ring Buffer 输出
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Per-CPU 临时存储
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_event);
} event_heap SEC(".maps");

// 配置 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} config_map SEC(".maps");

// Tail Call 程序数组
int stage_filter(void *ctx);
int stage_enrich(void *ctx);
int stage_output(void *ctx);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __array(values, int(void *));
} prog_array SEC(".maps") = {
    .values = {
        [0] = (void *)&stage_filter,
        [1] = (void *)&stage_enrich,
        [2] = (void *)&stage_output,
    },
};

// ========== 辅助函数 ==========

static __always_inline struct process_event *get_event_buf(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&event_heap, &zero);
}

static __always_inline struct filter_config *get_config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&config_map, &zero);
}

// ========== 入口点 ==========

SEC("tracepoint/sched/sched_process_exec")
int trace_exec_entry(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *event = get_event_buf();
    if (!event)
        return 0;

    // 基础信息收集
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->ktime = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // 读取 filename
    unsigned short offset = ctx->__data_loc_filename & 0xFFFF;
    char *filename = (char *)ctx + offset;
    bpf_probe_read_str(event->filename, sizeof(event->filename), filename);

    // 读取父进程
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Tail call 到过滤阶段
    bpf_tail_call(ctx, &prog_array, 0);
    return 0;
}

// ========== 过滤阶段 ==========

SEC("tracepoint")
int stage_filter(void *ctx)
{
    struct process_event *event = get_event_buf();
    struct filter_config *config = get_config();

    if (!event)
        return 0;

    // 应用过滤规则
    if (config && config->filter_enabled) {
        if (config->uid_filter != 0 && event->uid != config->uid_filter) {
            return 0;  // 不匹配，丢弃
        }
    }

    // 继续到丰富阶段
    bpf_tail_call(ctx, &prog_array, 1);
    return 0;
}

// ========== 数据丰富阶段 ==========

SEC("tracepoint")
int stage_enrich(void *ctx)
{
    struct process_event *event = get_event_buf();
    if (!event)
        return 0;

    // 读取命令行参数
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);

    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);

        if (arg_start && arg_end && arg_end > arg_start) {
            unsigned long arg_len = arg_end - arg_start;
            if (arg_len > sizeof(event->args) - 1)
                arg_len = sizeof(event->args) - 1;

            bpf_probe_read(event->args, arg_len, (void *)arg_start);
        }
    }

    // 继续到输出阶段
    bpf_tail_call(ctx, &prog_array, 2);
    return 0;
}

// ========== 输出阶段 ==========

SEC("tracepoint")
int stage_output(void *ctx)
{
    struct process_event *event = get_event_buf();
    if (!event)
        return 0;

    // 提交到 ring buffer
    struct process_event *output = bpf_ringbuf_reserve(&events, sizeof(*output), 0);
    if (!output)
        return 0;

    // 复制数据
    __builtin_memcpy(output, event, sizeof(*output));

    bpf_ringbuf_submit(output, 0);
    return 0;
}
```

---

## 4. Git Commit 学习要点

### 4.1 Bug 修复类

| Commit | 描述 | 学习点 |
|--------|------|--------|
| `8c41661ca` | BPF: Init execve entry members | 结构体初始化的重要性 |
| `786c2f6f3` | BPF: zero cleanup_key on exec | 防止用户态解析混乱 |
| `d1d22e637` | fix missing break statements | switch 语句的 fallthrough |
| `c40055150` | fix data source pt_regs resolve on arm64 | 多架构兼容性 |

**示例分析 - 初始化问题**:

```c
// 修复前: 未初始化可能导致随机数据
struct msg_execve_event *event;
event = map_lookup_elem(&execve_msg_heap_map, &zero);

// 修复后: 明确初始化关键字段
event->cleanup_key = (struct msg_execve_key){ 0 };
```

### 4.2 性能优化类

| Commit | 描述 | 优化技术 |
|--------|------|---------|
| `694edf9da` | Reduce map lookup per event | 减少 map 查找次数 |
| `a1dc80a25` | de-duplicate looping logic | 代码去重 |
| `66c0a0e5f` | return early on filter failure | 早返回优化 |

**示例分析 - 减少 Map 查找**:

```c
// 优化前: 多次查找同一个 map
val1 = bpf_map_lookup_elem(&mymap, &key);
// ... 一些代码 ...
val2 = bpf_map_lookup_elem(&mymap, &key);

// 优化后: 缓存查找结果
val = bpf_map_lookup_elem(&mymap, &key);
if (val) {
    // 使用 val 进行多次操作
}
```

### 4.3 新特性使用类

| Commit | 描述 | eBPF 新特性 |
|--------|------|-----------|
| `af2b494f9` | Add CONFIG_ITER_NUM bool | BPF Iterators |
| `25d204532` | Add fentry generic bpf object | fentry/fexit |
| `960bf5550` | support for CEL expressions | BPF 程序动态生成 |
| `ffe34b33c` | Use sleepable generic uprobe | Sleepable BPF |

---

## 5. eBPF 新特性应用

### 5.1 BPF Iterators (内核 5.15+)

**Tetragon 使用场景**: 遍历进程列表、路径组件

```c
// 配置检查
#ifdef CONFIG_ITER_NUM
    // 使用 bpf_for 进行有界循环
    int i;
    bpf_for(i, 0, MAX_PATH_COMPONENTS) {
        // 处理路径组件
    }
#else
    // 使用 #pragma unroll
    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        // 处理路径组件
    }
#endif
```

### 5.2 fentry/fexit (内核 5.5+)

比 kprobe/kretprobe 更高效的函数跟踪。

```c
// fentry: 函数入口
SEC("fentry/do_sys_openat2")
int BPF_PROG(fentry_openat2, int dfd, const char *filename, struct open_how *how)
{
    // 直接访问参数，不需要 PT_REGS_PARM
    bpf_printk("fentry: filename=%s", filename);
    return 0;
}

// fexit: 函数退出
SEC("fexit/do_sys_openat2")
int BPF_PROG(fexit_openat2, int dfd, const char *filename, struct open_how *how, long ret)
{
    // 可以同时访问参数和返回值
    bpf_printk("fexit: filename=%s, ret=%ld", filename, ret);
    return 0;
}
```

### 5.3 Sleepable BPF (内核 5.10+)

允许在 BPF 程序中调用可能睡眠的内核函数。

```c
// Tetragon 使用 sleepable uprobe 进行用户态内存读取
SEC("uprobe.s/target_func")  // .s 后缀表示 sleepable
int sleepable_uprobe(struct pt_regs *ctx)
{
    char buf[256];
    // bpf_copy_from_user 可能睡眠
    bpf_copy_from_user(buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
    return 0;
}
```

### 5.4 kprobe.multi (内核 5.18+)

一次挂载多个 kprobe，减少开销。

```c
// Tetragon 的多探针支持
#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/generic_kprobe"
#else
#define MAIN "kprobe/generic_kprobe"
#endif
```

---

## 6. 常见 Bug 和优化

### 6.1 验证器复杂度限制

**问题**: 程序太复杂，超过验证器限制

**解决方案**:
1. 使用 Tail Call 拆分程序
2. 使用 `relax_verifier()` 添加检查点
3. 减少分支和循环

```c
// Tetragon 的 relax_verifier 实现
FUNC_INLINE void relax_verifier(void)
{
    // 通过调用简单的 helper 添加验证点
    asm volatile("call 8;\n" ::
                 : "r0", "r1", "r2", "r3", "r4", "r5");
}
```

### 6.2 栈空间限制 (512 字节)

**问题**: BPF 栈只有 512 字节

**解决方案**: 使用 Per-CPU Array 作为堆

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct large_struct);  // 可以很大
} heap SEC(".maps");

SEC("kprobe/xxx")
int my_kprobe(void *ctx)
{
    __u32 zero = 0;
    struct large_struct *data = bpf_map_lookup_elem(&heap, &zero);
    if (!data)
        return 0;
    // 使用 data...
}
```

### 6.3 Map 并发访问

**问题**: 多 CPU 同时访问 Map 可能有竞争

**解决方案**:
1. 使用 Per-CPU Map
2. 使用原子操作
3. 使用 spin_lock (内核 5.1+)

```c
// 原子操作
__sync_fetch_and_add(&value, 1);

// Per-CPU 避免竞争
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    // ...
} percpu_map SEC(".maps");
```

### 6.4 字符串处理

**问题**: BPF 中字符串处理受限

**解决方案**:
1. 使用 `bpf_probe_read_str`
2. 注意返回值包含 null 终止符
3. 使用固定大小缓冲区

```c
// Tetragon 的字符串处理
char buf[256];
int len = bpf_probe_read_str(buf, sizeof(buf), src);
if (len > 0) {
    len--;  // 减去 null 终止符
}
```

---

## 7. 学习资源

### 7.1 官方文档
- [Linux BPF Documentation](https://docs.kernel.org/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [Cilium BPF Guide](https://docs.cilium.io/en/stable/bpf/)

### 7.2 推荐书籍
- "BPF Performance Tools" by Brendan Gregg
- "Learning eBPF" by Liz Rice

### 7.3 实践项目
- [bcc](https://github.com/iovisor/bcc) - BPF 工具集
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) - 项目模板
- [Tetragon](https://github.com/cilium/tetragon) - 本指南的参考项目

---

## 8. 下一步行动

1. **环境搭建**: 准备 Linux 开发环境，安装 clang、llvm、libbpf
2. **运行 Demo**: 从 Demo 1 开始，逐个运行和理解
3. **阅读源码**: 结合本指南阅读 Tetragon BPF 代码
4. **动手修改**: 尝试修改 Demo，添加自己的功能
5. **分析 Commit**: 挑选感兴趣的 commit 深入分析
