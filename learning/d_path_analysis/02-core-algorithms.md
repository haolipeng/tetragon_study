# 核心算法分析

本文档深入分析 `d_path_local` 的核心算法实现，包括逆向遍历原理和所有关键函数的逐行注释。

---

## 1. 逆向遍历算法原理

### 为什么采用逆向构造？

在内核中，我们拿到的是一个**文件的 dentry**，要构建完整路径，有两种策略：

| 策略 | 过程 | 问题 |
|-----|------|-----|
| 正向构造 | 从 "/" 开始，向下搜索到目标文件 | 需要遍历整个目录树，效率极低 |
| **逆向构造** | 从目标 dentry 出发，通过 d_parent 回溯到 "/" | 只需沿着一条路径，效率高 |

```
正向: 不知道往哪走
    /
   /|\
  ? ? ?      需要搜索整个树
 /|\ ...
? ? ?

逆向: 直接沿着 d_parent 回溯
    /  ←─────────────────┐
    |                    │
  home ←─────────────┐   │ d_parent
    |                │   │
  user ←─────────┐   │   │ d_parent
    |            │   │   │
test.txt ────────┴───┴───┘ 起点
```

### 缓冲区从末尾向前填充

逆向遍历的问题：**先获取的是最深层的目录名**。

```
遍历顺序: test.txt → user → home → /
期望结果: /home/user/test.txt

如果从缓冲区开头填充:
  第1步: "test.txt"
  第2步: "test.txtuser"  ← 错误！需要插入到前面

解决方案: 从缓冲区末尾向前填充!

缓冲区 (4096字节):
┌───────────────────────────────────────────────────┐
│                                                   │
└───────────────────────────────────────────────────┘
                                                    ^
                                                   res (初始指向末尾)

第1步: 插入 "/test.txt"
┌───────────────────────────────────────────────────┐
│                                       /test.txt  │
└───────────────────────────────────────────────────┘
                                       ^
                                      res

第2步: 插入 "/user"
┌───────────────────────────────────────────────────┐
│                                  /user/test.txt  │
└───────────────────────────────────────────────────┘
                                  ^
                                 res

第3步: 插入 "/home"
┌───────────────────────────────────────────────────┐
│                            /home/user/test.txt   │
└─────────────���─────────────────────────────────────┘
                            ^
                           res (最终返回这个指针)
```

---

## 2. 函数调用关系图

```
d_path_local()                    ← 入口函数
    │
    ├─→ map_lookup_elem()         ← 从 percpu map 获取缓冲区
    │
    └─→ __d_path_local()          ← 内部实现
            │
            ├─→ get_current_task() ← 获取当前进程
            │
            └─→ path_with_deleted() ← 处理已删除文件
                    │
                    ├─→ d_unlinked()  ← 检测文件是否已删除
                    │       │
                    │       ├─→ d_unhashed()
                    │       └─→ IS_ROOT()
                    │
                    ├─→ prepend()     ← 追加 " (deleted)" 标记
                    │
                    └─→ prepend_path() ← 核心：路径遍历
                            │
                            ├─→ real_mount()  ← vfsmount → mount 转换
                            │
                            └─→ cwd_read()    ← 循环调用，每次处理一级目录
                                    │
                                    ├─→ IS_ROOT()      ← 检测根目录
                                    └─→ prepend_name() ← 插入目录名到缓冲区
```

---

## 3. 关键函数逐行详解

### 函数 1: `d_path_local()` - 入口函数

**位置**: `bpf_d_path.h:336-352`

```c
FUNC_INLINE char *
d_path_local(const struct path *path, int *buflen, int *error)
{
    // ============ 第1步: 获取缓冲区 ============
    int zero = 0;
    char *buffer = 0;

    // 从 percpu array map 中获取预分配的 4096+256 字节缓冲区
    // 使用 map 而非栈内存，因为 eBPF 栈限制为 512 字节
    buffer = map_lookup_elem(&buffer_heap_map, &zero);
    if (!buffer)
        return 0;  // map 查找失败（理论上不会发生）

    // ============ 第2步: 初始化并调用内部实现 ============
    *buflen = MAX_BUF_LEN;  // 设置缓冲区大小为 4096

    // 调用内部实现函数进行路径解析
    // 返回值 buffer 指向路径字符串的起始位置
    buffer = __d_path_local(path, buffer, buflen, error);

    // ============ 第3步: 计算实际路径长度 ============
    // __d_path_local 返回后，*buflen 是剩余的缓冲区空间
    // 实际路径长度 = 初始长度 - 剩余长度
    if (*buflen > 0)
        *buflen = MAX_BUF_LEN - *buflen;

    return buffer;  // 返回路径字符串的起始指针
}
```

**图示**：
```
调用前:
  path ──→ 某个文件的 struct path

调用后:
  buffer ──→ "/home/user/test.txt"
  *buflen = 19 (路径长度)
  *error = 0 (成功) 或 UNRESOLVED_PATH_COMPONENTS (路径未完全解析)
```

---

### 函数 2: `__d_path_local()` - 内部实现

**位置**: `bpf_d_path.h:310-321`

```c
FUNC_INLINE char *
__d_path_local(const struct path *path, char *buf, int *buflen, int *error)
{
    // ============ 第1步: 初始化指针位置 ============
    // res 指向缓冲区末尾，路径将从这里向前填充
    char *res = buf + *buflen;

    struct task_struct *task;
    struct fs_struct *fs;

    // ============ 第2步: 获取当前进程的根目录 ============
    // 获取当前执行上下文的 task_struct
    task = (struct task_struct *)get_current_task();

    // 读取进程的 fs_struct（包含 root 和 pwd）
    // 注意: 使用 probe_read 安全访问内核内存
    probe_read(&fs, sizeof(fs), _(&task->fs));

    // ============ 第3步: 执行路径解析 ============
    // path: 要解析的目标路径
    // &fs->root: 当前进程的根目录（作为遍历终点）
    // buf: 缓冲区起始地址
    // &res: 当前写入位置（会被更新）
    // buflen: 剩余空间（会被更新）
    *error = path_with_deleted(path, _(&fs->root), buf, &res, buflen);

    return res;  // 返回路径字符串起始位置
}
```

**关键点：为什么使用 `fs->root` 作为终点？**

```
普通进程:
  fs->root = /        ← 文件系统根目录

chroot 环境:
  fs->root = /var/jail  ← chroot 的根目录

容器环境:
  fs->root = /          ← 容器内的 "/"（实际是宿主机的某个目录）

路径解析到 fs->root 就停止，保证路径相对于进程可见的根目录
```

---

### 函数 3: `path_with_deleted()` - 删除文件检测

**位置**: `bpf_d_path.h:259-273`

```c
FUNC_INLINE int
path_with_deleted(const struct path *path, const struct path *root, char *bf,
                  char **buf, int *buflen)
{
    struct dentry *dentry;

    // ============ 第1步: 获取目标 dentry ============
    probe_read(&dentry, sizeof(dentry), _(&path->dentry));

    // ============ 第2步: 检测文件是否已被删除 ============
    // d_unlinked() 检测: 文件已从目录中移除但仍被打开
    // 典型场景: 进程打开文件��，文件被 rm 删除
    if (d_unlinked(dentry)) {
        // 在路径末尾追加 " (deleted)" 标记
        // 例如: "/tmp/test.txt (deleted)"
        int error = prepend(buf, buflen, " (deleted)", 10);

        if (error)  // 缓冲区不足（实际不会发生）
            return error;
    }

    // ============ 第3步: 执行主路径解析 ============
    return prepend_path(path, root, bf, buf, buflen);
}
```

**删除文件的例子**：
```bash
# 场景演示
$ cat /tmp/test.txt &   # 后台进程打开文件
[1] 12345

$ rm /tmp/test.txt      # 删除文件

$ ls -l /proc/12345/fd/3
lr-x------ 1 user user 64 Jan 1 00:00 /proc/12345/fd/3 -> '/tmp/test.txt (deleted)'
```

---

### 函数 4: `prepend_path()` - 路径遍历核心

**位置**: `bpf_d_path.h:212-257`

```c
FUNC_INLINE int
prepend_path(const struct path *path, const struct path *root, char *bf,
             char **buffer, int *buflen)
{
    // ============ 第1步: 初始化遍历状态 ============
    struct cwd_read_data data = {
        .bf = bf,           // 缓冲区起始地址
        .bptr = *buffer,    // 当前写入位置（从末尾开始）
        .blen = *buflen,    // 剩余缓冲区空间
    };
    int idx, error = 0;

    // ============ 第2步: 读取根路径信息（遍历终点） ============
    probe_read(&data.root_dentry, sizeof(data.root_dentry), _(&root->dentry));
    probe_read(&data.root_mnt, sizeof(data.root_mnt), _(&root->mnt));

    // ============ 第3步: 读取目标路径信息（遍历起点） ============
    probe_read(&data.dentry, sizeof(data.dentry), _(&path->dentry));
    probe_read(&data.vfsmnt, sizeof(data.vfsmnt), _(&path->mnt));

    // vfsmount 转换为 mount 结构（通过 container_of）
    data.mnt = real_mount(data.vfsmnt);

    // ============ 第4步: 循环遍历目录项 ============
    // 根据内核版本和配置选择不同的循环方式
    if (CONFIG(ITER_NUM)) {
        // 新版内核: 使用 bpf_for (BPF 迭代器)
        bpf_for(idx, 0, PROBE_CWD_READ_ITERATIONS) {
            if (cwd_read(&data))  // 返回 1 表示完成
                break;
        }
    } else {
#ifndef __V61_BPF_PROG
        // 旧版内核: 使用编译时展开的循环
        #pragma unroll
        for (int i = 0; i < PROBE_CWD_READ_ITERATIONS; ++i) {
            if (cwd_read(&data))
                break;
        }
#else
        // v6.1+ 内核: 使用 bpf_loop helper
        loop(PROBE_CWD_READ_ITERATIONS, cwd_read_v61, (void *)&data, 0);
#endif
    }

    // ============ 第5步: 处理结果 ============
    // 如果指针没有移动，说明是根目录本身
    if (data.bptr == *buffer) {
        *buflen = 0;
        return 0;
    }

    // 检查路径是否完全解析
    if (!data.resolved)
        error = UNRESOLVED_PATH_COMPONENTS;  // 路径太深或太长

    *buffer = data.bptr;  // 更新缓冲区指针
    *buflen = data.blen;  // 更新剩余空间
    return error;
}
```

**`cwd_read_data` 结构体详解**：

```c
struct cwd_read_data {
    struct dentry *root_dentry;  // 进程根目录的 dentry（终点）
    struct vfsmount *root_mnt;   // 进程根目录的挂载点
    char *bf;                    // 缓冲区起始地址
    struct dentry *dentry;       // 当前正在处理的 dentry
    struct vfsmount *vfsmnt;     // 当前的挂载点
    struct mount *mnt;           // 当前的 mount 结构
    char *bptr;                  // 缓冲区当前写入位置
    int blen;                    // 缓冲区剩余空间
    bool resolved;               // 是否成功解析到根
};
```

---

### 函数 5: `cwd_read()` - 单次迭代逻辑（最核心！）

**位置**: `bpf_d_path.h:156-203`

这是整个路径解析的**核心函数**，每次调用处理**一级目录**：

```c
FUNC_INLINE long cwd_read(struct cwd_read_data *data)
{
    struct qstr d_name;
    struct dentry *parent;
    struct dentry *vfsmnt_mnt_root;
    struct dentry *dentry = data->dentry;
    struct vfsmount *vfsmnt = data->vfsmnt;
    struct mount *mnt = data->mnt;
    int error;

    // ========== 检查1: 是否到达进程根目录？ ==========
    // 如果当前 dentry 和 vfsmount 都与 root 相同，说明到达终点
    if (!(dentry != data->root_dentry || vfsmnt != data->root_mnt)) {
        data->resolved = true;  // 标记成功完成
        return 1;               // 返回 1 结束循环
    }

    // ========== 检查2: 是否到达当前文件系统的根/挂载点？ ==========
    // 读取当前挂载点的根 dentry
    probe_read(&vfsmnt_mnt_root, sizeof(vfsmnt_mnt_root), _(&vfsmnt->mnt_root));

    // 两种情况需要跨挂载点:
    // 1. dentry == vfsmnt_mnt_root: 到达当前文件系统的根
    // 2. IS_ROOT(dentry): dentry 的 d_parent 指向自己（根目录特征）
    if (dentry == vfsmnt_mnt_root || IS_ROOT(dentry)) {
        struct mount *parent;

        // 获取父挂载点
        probe_read(&parent, sizeof(parent), _(&mnt->mnt_parent));

        // 检查是否还有父挂载点（不是全局根）
        if (data->mnt != parent) {
            // ====== 跨挂载点处理 ======
            // 获取挂载点在父文件系统中的 dentry
            probe_read(&data->dentry, sizeof(data->dentry),
                       _(&mnt->mnt_mountpoint));
            // 切换到父挂载点
            data->mnt = parent;
            data->vfsmnt = _(&parent->mnt);
            return 0;  // 继续迭代
        }

        // 到达全局根目录
        data->resolved = true;
        return 1;  // 完成
    }

    // ========== 正常情况: 处理当前目录项 ==========
    // 读取父 dentry
    probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
    // 读取当前 dentry 的名称
    probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));

    // 将目录名插入缓冲区（前置）
    error = prepend_name(data->bf, &data->bptr, &data->blen,
                         (const char *)d_name.name, d_name.len);

    // 缓冲区溢出
    if (error)
        return 1;  // 停止迭代（resolved = false）

    // 移动到父目录，准备下一次迭代
    data->dentry = parent;
    return 0;  // 继续迭代
}
```

**流程图**：

```
                    ┌─────────────────────┐
                    │   cwd_read() 开始   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ dentry == root &&   │──── 是 ────→ resolved=true
                    │ vfsmnt == root_mnt? │              return 1 (完成)
                    └──────────┬──────────┘
                               │ 否
                    ┌──────────▼──────────┐
                    │ dentry == mnt_root  │──── 是 ──┐
                    │ 或 IS_ROOT(dentry)? │          │
                    └──────────┬──────────┘          │
                               │ 否                  │
                               │         ┌───────────▼───────────┐
                               │         │  mnt != mnt_parent?   │
                               │         └───────────┬───────────┘
                               │                是   │   否
                               │         ┌──────────┘   │
                               │         │              ▼
                               │         │        resolved=true
                               │         │        return 1
                               │         ▼
                               │   ┌─────────────────┐
                               │   │ 跨挂载点:       │
                               │   │ dentry=mountpoint│
                               │   │ mnt=parent      │
                               │   │ return 0 (继续) │
                               │   └─────────────────┘
                    ┌──────────▼──────────┐
                    │ 读取 d_parent       │
                    │ 读取 d_name         │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ prepend_name()      │──── 失败 ──→ return 1 (停止)
                    │ 插入目录名到缓冲区   │
                    └──────────┬──────────┘
                               │ 成功
                    ┌──────────▼──────────┐
                    │ dentry = parent     │
                    │ return 0 (继续)     │
                    └─────────────────────┘
```

---

### 函数 6: `prepend_name()` - 目录名插入

**位置**: `bpf_d_path.h:112-154`

```c
FUNC_INLINE int
prepend_name(char *buf, char **bufptr, int *buflen, const char *name, u32 namelen)
{
    // 标记: 是否能写入斜杠前缀
    bool write_slash = 1;

    // 计算当前位置相对于缓冲区起始的偏移
    u64 buffer_offset = (u64)(*bufptr) - (u64)buf;

    // ========== 处理名称过长的情况 ==========
    // 如果名称比剩余空间还长，截取能放下的部分（保留末尾）
    if (namelen >= *buflen) {
        name += namelen - *buflen;  // 跳过前面放不下的部分
        namelen = *buflen;          // 只复制能放下的长度
        write_slash = 0;            // 没空间写斜杠了
    }

    // 减少剩余空间计数
    *buflen -= (namelen + write_slash);

    // ========== 边界检查 ==========
    if (namelen + write_slash > buffer_offset)
        return -ENAMETOOLONG;  // 缓冲区溢出

    // 计算新的写入位置
    buffer_offset -= (namelen + write_slash);

    // 安全检查（让 eBPF 验证器满意）
    if (buffer_offset >= MAX_BUF_LEN)
        return -ENAMETOOLONG;

    // ========== 写入斜杠 ==========
    if (write_slash)
        buf[buffer_offset] = '/';

    // ========== 写入目录名 ==========
    // 使用内联汇编确保 namelen < 256（满足验证器）
    // 这也符合 Linux 最大文件名长度 255 字节的限制
    asm volatile("%[namelen] &= 0xff;\n"
                 : [namelen] "+r"(namelen));

    // 从内核内存复制目录名到缓冲区
    probe_read(buf + buffer_offset + write_slash, namelen * sizeof(char), name);

    // 更新缓冲区指针
    *bufptr = buf + buffer_offset;

    // 返回值: 0 表示成功，-ENAMETOOLONG 表示名称被截断
    return write_slash ? 0 : -ENAMETOOLONG;
}
```

**缓冲区填充过程示例**：

```
解析路径: /home/user/test.txt

初始状态 (buflen=4096):
┌────────────────────────────────────────────────┐
│                                                │
└────────────────────────────────────────────────┘
                                                 ^
                                              bufptr

第1次 prepend_name("test.txt", 8):
┌────────────────────────────────────────────────┐
│                                    /test.txt  │
└────────────────────────────────────────────────┘
                                    ^
                                 bufptr
                                 (buflen=4086)

第2次 prepend_name("user", 4):
┌────────────────────────────────────────────────┐
│                               /user/test.txt  │
└────────────────────────────────────────────────┘
                               ^
                            bufptr
                            (buflen=4081)

第3次 prepend_name("home", 4):
┌────────────────────────────────────────────────┐
│                          /home/user/test.txt  │
└────────────────────────────────────────────────┘
                          ^
                       bufptr (最终返回)
                       (buflen=4076)

最终路径长度 = 4096 - 4076 = 20 字节
```

---

## 4. 辅助函数

### IS_ROOT() - 判断根目录

```c
FUNC_INLINE bool IS_ROOT(struct dentry *dentry)
{
    struct dentry *d_parent;
    probe_read(&d_parent, sizeof(d_parent), _(&dentry->d_parent));
    return (dentry == d_parent);  // 根目录的 d_parent 指向自己
}
```

### d_unlinked() - 判断文件是否已删除

```c
FUNC_INLINE int d_unlinked(struct dentry *dentry)
{
    return d_unhashed(dentry) && !IS_ROOT(dentry);
}
```

### real_mount() - vfsmount 转 mount

```c
FUNC_INLINE struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of_btf(mnt, struct mount, mnt);
}
```

---

## 5. 本章小结

| 函数 | 核心职责 | 关键技术点 |
|-----|---------|-----------|
| `d_path_local` | 入口，获取缓冲区 | percpu map 避免栈溢出 |
| `__d_path_local` | 获取进程根目录 | `get_current_task()` |
| `path_with_deleted` | 处理已删除文件 | `d_unlinked()` 检测 |
| `prepend_path` | 循环控制 | 多种循环方式适配不同内核 |
| `cwd_read` | 单次目录项处理 | 挂载点跨越逻辑 |
| `prepend_name` | 目录名插入 | 从末尾向前填充 |

---

## 下一步

继续阅读 [03-eBPF限制与方案.md](03-eBPF限制与方案.md) 了解 eBPF 环境下的挑战与解决方案。
