# eBPF 限制与解决方案

本文档分析 `d_path_local` 如何巧妙地绕过 eBPF 的各种限制。

---

## 1. eBPF 的主要限制

eBPF 程序运行在内核中，为了保证安全性和稳定性，有严格的限制：

```
┌─────────────────────────────────────────────────────────────────────┐
│                       eBPF 程序限制                                  │
├─────────────────────────────────────────────────────────────────��───┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐│
│  │  栈空间     │  │  指令数     │  │  循环      │  │  内存访问   ││
│  │  512 字节   │  │  100万条    │  │  需有界    │  │  需验证     ││
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘│
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  函数调用   │  │  map 大小   │  │  尾调用    │                 │
│  │  深度受限   │  │  有上限     │  │  次数受限  │                 │
│  └─────��───────┘  └─────────────┘  └─────────────┘                 │
│                                                                     │
└────────────���────────────────────────────────────────────────────────┘
```

### 限制 1: 栈空间限制 - 512 字节

```c
// 错误示例：会导致验证失败
int my_bpf_prog() {
    char buffer[4096];  // 错误！超过 512 字节栈限制
    // ...
}
```

**问题**：`d_path_local` 需要 4096 字节缓冲区存储路径，远超 512 字节限制。

### 限制 2: 指令数限制

| 内核版本 | 指令数限制 |
|---------|-----------|
| < 5.2 | 4096 条 |
| 5.2+ | 100 万条 |

**问题**：路径遍历循环展开后可能产生大量指令。

### 限制 3: 循环限制

```c
// 错误示例：无界循环
while (dentry != root) {  // 验证器无法确定循环次数
    dentry = dentry->d_parent;
}
```

**问题**：路径深度不确定，需要动态循环。

### 限制 4: 内存访问限制

```c
// 错误示例：直接解引用内核指针
char *name = dentry->d_name.name;  // 可能导致内核崩溃！
```

**问题**：必须使用安全的内存读取方式。

---

## 2. Tetragon 的解决方案

### 方案 1: percpu map 替代栈内存

**问题**：需要 4096 字节缓冲区，但栈只有 512 字节。

**解决**：使用 BPF_MAP_TYPE_PERCPU_ARRAY 预分配缓冲区。

```c
// 定义 (bpf_d_path.h:38-51)
struct buffer_heap_map_value {
    // 4096 + 256 字节（额外空间给验证器一些余量）
    unsigned char buf[MAX_BUF_LEN + 256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // 每 CPU 一份，避免竞争
    __uint(max_entries, 1);                    // 只需要一个条目
    __type(key, int);
    __type(value, struct buffer_heap_map_value);
} buffer_heap_map SEC(".maps");

// 使用 (d_path_local 函数中)
int zero = 0;
char *buffer = map_lookup_elem(&buffer_heap_map, &zero);
```

**原理图**：

```
传统方式（失败）:                 Tetragon 方案:
┌──────────────┐                 ┌──────────────────────────┐
│  eBPF 栈     │                 │    buffer_heap_map       │
│  512 字节    │                 │   (PERCPU_ARRAY)         │
├──────────────┤                 ├──────────────────────────┤
│  char buf    │ ← 超限!         │  CPU 0: [4352 bytes]    │
│  [4096]      │                 │  CPU 1: [4352 bytes]    │
│              │                 │  CPU 2: [4352 bytes]    │
│              │                 │  ...                     │
└──────────────┘                 └──────────────────────────┘
                                          ↓
                                 map_lookup_elem(&map, &0)
                                          ↓
                                 返回当前 CPU 的缓冲区指针
```

**为什么用 PERCPU？**
- 每个 CPU 独立缓冲区，无需加锁
- 避免多 CPU 并发访问冲突
- 性能最优

---

### 方案 2: 多种循环策略适配不同内核

**问题**：不同内核版本对循环的支持不同。

**解决**：条件编译，根据内核版本选择最佳方案。

```c
// 配置 (bpf_d_path.h:21-29)
#ifndef __V61_BPF_PROG
  #ifdef __LARGE_BPF_PROG
    #define PROBE_CWD_READ_ITERATIONS 128   // 大型程序：128 次
  #else
    #define PROBE_CWD_READ_ITERATIONS 11    // 小型程序：11 次
  #endif
#else
  #define PROBE_CWD_READ_ITERATIONS 2048    // v6.1+ 内核：2048 次
#endif
```

**三种循环实现**：

```c
// prepend_path 函数中 (bpf_d_path.h:230-246)

if (CONFIG(ITER_NUM)) {
    // ====== 方案 A: BPF 迭代器（最新内核特性）======
    // bpf_for 是语法糖，底层使用 bpf_iter
    bpf_for(idx, 0, PROBE_CWD_READ_ITERATIONS) {
        if (cwd_read(&data))
            break;
    }
} else {
#ifndef __V61_BPF_PROG
    // ====== 方案 B: 编译时循环展开 ======
    // #pragma unroll 告诉编译器展开循环
    // 缺点：代码膨胀，指令数增加
    #pragma unroll
    for (int i = 0; i < PROBE_CWD_READ_ITERATIONS; ++i) {
        if (cwd_read(&data))
            break;
    }
#else
    // ====== 方案 C: bpf_loop helper (v5.17+) ======
    // 内核提供的有界循环辅助函数
    loop(PROBE_CWD_READ_ITERATIONS, cwd_read_v61, (void *)&data, 0);
#endif
}
```

**各方案对比**：

```
┌──────────────┬─────────────────┬─────────────────┬─────────────────┐
│    方案      │  适用内核版本   │      优点        │      缺点       │
├──────────────┼─────────────────┼─────────────────┼─────────────────┤
│ bpf_for      │ 最新内核        │ 简洁、高效      │ 需要新内核      │
│ (BPF 迭代器) │ (有 ITER_NUM)   │ 支持大迭代次数  │                 │
├──────────────┼─────────────────┼─────────────────┼─────────────────┤
│ #pragma      │ 旧内核          │ 兼容性好        │ 代码膨胀        │
│ unroll       │ (非 v6.1)       │                 │ 迭代次数受限    │
├──────────────┼─────────────────┼─────────────────┼─────────────────┤
│ bpf_loop     │ v5.17 - v6.1    │ 支持更多迭代    │ 回调函数开销    │
│              │                 │ 不膨胀代码      │                 │
└──────────────┴─────────────────┴─────────────────┴─────────────────┘
```

**循环展开示意**：

```
#pragma unroll 效果 (ITERATIONS=3):

源代码:                          展开后:
for (i=0; i<3; i++) {           if (cwd_read(&data)) goto end;
    if (cwd_read(&data))        if (cwd_read(&data)) goto end;
        break;                   if (cwd_read(&data)) goto end;
}                               end:

优点: 验证器能确定循环有界
缺点: 如果 ITERATIONS=128，代码膨胀 128 倍！
```

---

### 方案 3: probe_read 安全访问内核内存

**问题**：直接解引用内核指针可能导致崩溃。

**解决**：使用 `probe_read` / `probe_read_kernel` 安全读取。

```c
// 错误方式（危险！）
struct dentry *parent = dentry->d_parent;  // 直接解引用

// 正确方式（安全）
struct dentry *parent;
probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
```

**probe_read 的作用**：

```
┌────────────────────────────────────────────────────────────────┐
│                       probe_read 工作原理                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. 检查源地址是否有效（内核地址空间内）                         │
│  2. 如果有效，安全复制数据到目标地址                            │
│  3. 如果无效，返回错误码而不是崩溃                              │
│                                                                │
│  ┌─────────┐      probe_read       ┌─────────┐                │
│  │ 内核内存 │ ─���────────────────→ │ eBPF 栈  │                │
│  │ (可能    │   安全复制           │ 或 map  │                │
│  │  无效)   │                      │          │                │
│  └─────────┘                       └─────────┘                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**`_()` 宏的作用**：

```c
// _ 宏用于 BTF (BPF Type Format) 兼容
// 保持字段偏移信息，支持 CO-RE (Compile Once Run Everywhere)
#define _(P) ({                                          \
    typeof(P) __tmp;                                     \
    __builtin_preserve_access_index(__tmp = (P));        \
    __tmp;                                               \
})

// 使用示例
probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
//                                   ↑
//                          CO-RE: 即使内核版本不同，
//                          字段偏移也能自动适配
```

---

### 方案 4: 边界检查满足验证器

**问题**：eBPF 验证器需要证明所有内存访问都是安全的。

**解决**：显式添加边界检查。

```c
// prepend_name 函数中的边界检查 (bpf_d_path.h:139-150)

// 检查 1: 确保 buffer_offset 不会越界
if (buffer_offset >= MAX_BUF_LEN)
    return -ENAMETOOLONG;

// 检查 2: 使用内联汇编限制 namelen 为 0-255
// 这让验证器知道 probe_read 的长度是安全的
asm volatile("%[namelen] &= 0xff;\n"
             : [namelen] "+r"(namelen));

// 现在验证器知道:
// - buffer_offset < 4096
// - namelen <= 255
// 所以 probe_read(buf + offset, namelen, ...) 是安全的
probe_read(buf + buffer_offset + write_slash, namelen * sizeof(char), name);
```

**验证器的思维过程**：

```
验证器分析:
┌────────────────────────────────────────────────────────────────┐
│ probe_read(buf + buffer_offset + write_slash, namelen, name)  │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│ 问题1: buffer_offset 的范围是什么？                            │
│   ✓ 代码检查了 buffer_offset >= MAX_BUF_LEN                    │
│   → 所以 buffer_offset ∈ [0, 4095]                             │
│                                                                │
│ 问题2: namelen 的范围是什么？                                  │
│   ✓ asm 指令限制 namelen &= 0xff                               │
│   → 所以 namelen ∈ [0, 255]                                    │
│                                                                │
│ 问题3: write_slash 的范围是什么？                              │
│   ✓ bool 类型                                                  │
│   → write_slash ∈ [0, 1]                                       │
│                                                                │
│ 结论: 访问范围 = [buf, buf + 4095 + 1 + 255]                   │
│       缓冲区大小 = 4096 + 256 = 4352                           │
│       访问安全！✓                                              │
└────────────────────────────────────────────────────────────────┘
```

这就是为什么 `buffer_heap_map_value` 定义为 `MAX_BUF_LEN + 256` 字节！

---

### 方案 5: container_of_btf 进行结构转换

**问题**：需要从 `vfsmount` 指针获取包含它的 `mount` 结构。

**解决**：使用 container_of 宏进行指针运算。

```c
// 定义 (bpf_d_path.h:31-37)
#define offsetof_btf(s, memb) \
    ((size_t)((char *)_(&((s *)0)->memb) - (char *)0))

#define container_of_btf(ptr, type, member)                      \
    ({                                                           \
        void *__mptr = (void *)(ptr);                            \
        ((type *)(__mptr - offsetof_btf(type, member)));         \
    })

// 使用 (bpf_d_path.h:53-56)
FUNC_INLINE struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of_btf(mnt, struct mount, mnt);
}
```

**原理图**：

```
struct mount 内存布局:
┌─────────────────────────────────────────┐
│  mnt_parent                             │  ← mount 起始地址
├─────────────────────────────────────────┤
│  mnt_mountpoint                         │
├─────────────────────────────────────────┤
│  mnt_root                               │
├─────────────────────────────────────────┤
│  ...                                    │
├─────────────────────────────────────────┤
│  struct vfsmount mnt  ←─────────────────┼─── 我们有这个指针
│    - mnt_root                           │
│    - mnt_sb                             │
│    - mnt_flags                          │
├─────────────────────────────────────────┤
│  ...                                    │
└─────────────────────────────────────────┘

container_of 计算:
  mount_ptr = vfsmount_ptr - offsetof(struct mount, mnt)
```

---

## 3. 限制与方案对照表

| 限制 | 具体约束 | Tetragon 方案 | 代码位置 |
|-----|---------|--------------|---------|
| 栈空间 | 512 字节 | percpu array map | 46-51 行 |
| 循环 | 需有界 | unroll / bpf_loop / bpf_for | 230-246 行 |
| 内存访问 | 需验证 | probe_read + 边界检查 | 全文 |
| 指令数 | 100万条 | 条件编译减少迭代次数 | 21-29 行 |
| 结构转换 | 需 BTF | container_of_btf | 33-37 行 |

---

## 4. eBPF 程序复杂度控制

```
// 不同配置下的复杂度
┌─────────────────┬────────────────┬─────────────────┐
│      配置       │  迭代次数      │   代码膨胀倍数   │
├─────────────────┼────────────────┼─────────────────┤
│ 小型程序        │      11        │      11x        │
│ 大型程序        │     128        │     128x        │
│ v6.1+ (bpf_for) │    2048        │      1x         │
└─────────────────┴────────────────┴─────────────────┘

小型程序 (11次迭代):
  最大路径深度: 11 级目录
  例如: /a/b/c/d/e/f/g/h/i/j/k  (刚好 11 级)

大型程序 (128次迭代):
  最大路径深度: 128 级目录
  几乎覆盖所有实际场景

v6.1+ 内核 (2048次迭代):
  使��� bpf_for，无代码膨胀
  支持极深路径
```

---

## 5. 本章小结

| 挑战 | 解决方案 | 关键技术 |
|-----|---------|---------|
| 栈空间 512 字节限制 | 使用 percpu array map 存储 4KB 缓冲区 | BPF_MAP_TYPE_PERCPU_ARRAY |
| 循环需有界 | 根据内核版本选择 unroll/bpf_loop/bpf_for | 条件编译 |
| 内存访问需验证 | 使用 probe_read + 显式边界检查 | asm volatile 限制范围 |
| 跨内核版本兼容 | BTF + CO-RE 技术 | `_()` 宏保持字段偏移 |
| 结构体指针转换 | container_of_btf 宏 | offsetof 计算 |

---

## 下一步

继续阅读 [04-挂载点处理.md](04-挂载点处理.md) 了解跨挂载点路径解析的详细机制。
