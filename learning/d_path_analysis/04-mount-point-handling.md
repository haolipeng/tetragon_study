# 挂载点处理详解

本文档深入分析 `d_path_local` 如何处理跨挂载点的路径解析，这是理解整个实现最复杂的部分。

---

## 1. Linux 挂载点基础回顾

### 什么是挂载点？

Linux 将所有文件系统组织成一棵统一的目录树，通过**挂载（mount）**将不同的文件系统连接在一起。

```bash
# 查看系统挂载点
$ mount
/dev/sda1 on / type ext4 (rw,relatime)
/dev/sda2 on /home type ext4 (rw,relatime)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev)
/dev/sdb1 on /mnt/usb type vfat (rw,relatime)
```

```
                        单一目录树视图
                              /
                             /|\
                            / | \
                           /  |  \
                         home tmp  mnt
                          |    |    |
                        user  ...  usb
                          |         |
                       test.txt  photo.jpg

实际上由 4 个文件系统组成:
┌──────────────────────────────────────────────────────────────┐
│  /          ext4 (sda1)     ← 根文件系统                     │
│  /home      ext4 (sda2)     ← 单独分区                       │
│  /tmp       tmpfs           ← 内存文件系统                   │
│  /mnt/usb   vfat (sdb1)     ← U盘                           │
└──────────────────────────────────────────────────────────────┘
```

### mount 与 vfsmount 的关系

```c
struct mount {
    struct mount *mnt_parent;      // 父挂载点
    struct dentry *mnt_mountpoint; // 在父文件系统中的挂载位置
    struct vfsmount mnt;           // 内嵌的 vfsmount（对外接口）
    // ...
};

struct vfsmount {
    struct dentry *mnt_root;       // 此文件系统的根 dentry
    struct super_block *mnt_sb;    // 超级块
    int mnt_flags;                 // 挂载标志
};
```

**关键关系图**：

```
struct mount 与 struct vfsmount 的关系:

┌───────────────────────────────────────┐
│          struct mount                 │
├───────────────────────────────────────┤
│  mnt_parent ──────────────→ 父 mount  │
├───────────────────────────────────────┤
│  mnt_mountpoint ──────────→ 父文件    │
│                             系统中的  │
│                             dentry    │
├───────────────────────────────────────┤
│  ┌─────────────────────────────────┐  │
│  │      struct vfsmount mnt        │  │ ← 内嵌结构
│  ├─────────────────────────────────┤  │
│  │  mnt_root ────→ 本文件系统根    │  │
│  │  mnt_sb ──────→ 超级块          │  │
│  │  mnt_flags                      │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
        ↑
        │
  container_of(vfsmount_ptr, struct mount, mnt)
        │
        ↓
  如果只有 vfsmount 指针，可以通过 container_of 获取 mount
```

---

## 2. 挂载点层次结构示例

假设系统有以下挂载：
- `/` 挂载 ext4 分区
- `/home` 挂载另一个 ext4 分区

```
┌─────────────────────────────────────────────────────────────────────┐
│                          挂载点层次结构                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  mount_根 (/)                        mount_home (/home)             │
│  ┌─────────────────────┐            ┌─────────────────────┐        │
│  │ mnt_parent = self   │←───────────│ mnt_parent          │        │
│  │ mnt_mountpoint = 无 │            │ mnt_mountpoint ─────┼───┐    │
│  │                     │            │                     │   │    │
│  │ mnt.mnt_root ───────┼─→ "/"      │ mnt.mnt_root ───────┼─→│"/" │
│  │ (根文件系统的根)     │            │ (home分区的根)       │   │    │
│  └─────────────────────┘            └─────────────────────┘   │    │
│                                                               │    │
│  根文件系统的目录树:              home 分区的目录树:           │    │
│  ┌───────────┐                   ┌───────────┐                │    │
│  │ dentry "/" │                   │ dentry "/" │ ← mnt_root    │    │
│  └─────┬─────┘                   └─────┬─────┘                │    │
│        │                               │                      │    │
│  ┌─────┴─────┐                   ┌─────┴─────┐                │    │
│  │  "home"   │←──────────────────┼───────────┼────────────────┘    │
│  │  "etc"    │  mnt_mountpoint   │  "user"   │                     │
│  │  "tmp"    │                   └─────┬─────┘                     │
│  └───────────┘                         │                           │
│                                  ┌─────┴─────┐                     │
│                                  │"test.txt" │                     │
│                                  └───────────┘                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. 跨挂载点路径解析过程

现在来看 `cwd_read()` 如何处理跨挂载点的情况。

### 场景：解析 `/home/user/test.txt`

```
目标: 从 test.txt 的 dentry 解析出完整路径 "/home/user/test.txt"

初始状态:
  data.dentry  = dentry("test.txt")  ← 在 home 分区内
  data.vfsmnt  = mount_home.mnt      ← home 分区的挂载
  data.mnt     = mount_home          ← home 分区的 mount 结构
```

### 第 1-2 次迭代：在 home 分区内遍历

```
第 1 次 cwd_read():
┌─────────────────────────────────────────────��──────────────────────┐
│ 当前: dentry = "test.txt"                                          │
│                                                                    │
│ 检查1: dentry == root_dentry && vfsmnt == root_mnt?                │
│        "test.txt" != "/" && mount_home != mount_根  → 否，继续     │
│                                                                    │
│ 检查2: dentry == mnt_root || IS_ROOT(dentry)?                      │
│        "test.txt" != "/" (home分区根) → 否，正常处理               │
│                                                                    │
│ 操作: prepend_name("test.txt")                                     │
│       缓冲区: [                                    /test.txt]      │
│       dentry = d_parent = "user"                                   │
│                                                                    │
│ 返回 0 (继续迭代)                                                   │
└────────────────────────────────────────────────────────────────────┘

第 2 次 cwd_read():
┌─────────────────────────────────────────────────────────────────���──┐
│ 当前: dentry = "user"                                              │
│                                                                    │
│ 检查1: 否                                                          │
│ 检查2: "user" != "/" (home分区根) → 否                             │
│                                                                    │
│ 操作: prepend_name("user")                                         │
│       缓冲区: [                               /user/test.txt]      │
│       dentry = d_parent = "/" (home分区的根)                       │
│                                                                    │
│ 返回 0 (继续迭代)                                                   │
└────────────────────────────────────────────────────────────────────┘
```

### 第 3 次迭代：到达 home 分区根，需要跨挂载点

```
第 3 次 cwd_read():  ★ 关键！跨挂载点 ★
┌────────────────────────────────────────────────────────────────────┐
│ 当前: dentry = "/" (home 分区的根 dentry)                          │
│       vfsmnt = mount_home.mnt                                      │
│       mnt = mount_home                                             │
│                                                                    │
│ 检查1: dentry == root_dentry && vfsmnt == root_mnt?                │
│        "/" != 进程根 → 否，继续                                     │
│                                                                    │
│ 检查2: dentry == mnt_root?                                         │
│        "/" == mount_home.mnt.mnt_root  → 是！                      │
│                                                                    │
│ ===== 进入跨挂载点处理分支 =====                                    │
│                                                                    │
│ 读取父挂载点:                                                       │
│   parent = mnt->mnt_parent = mount_根                              │
│                                                                    │
│ 检查: mnt != parent?                                               │
│       mount_home != mount_根 → 是，需要跨越                        │
│                                                                    │
│ 执行跨挂载点操作:                                                   │
│   data.dentry = mnt->mnt_mountpoint = "home" (在根文件系统中)       │
│   data.mnt = parent = mount_根                                     │
│   data.vfsmnt = &mount_根.mnt                                      │
│                                                                    │
│ 注意: 本次迭代没有调用 prepend_name！                               │
│       缓冲区不变: [                          /user/test.txt]       │
│                                                                    │
│ 返回 0 (继续迭代)                                                   │
└────────────────────────────────────────────────────────────────────┘
```

### 第 4-5 次迭代：在根文件系统中继续

```
第 4 次 cwd_read():
┌────────────────────────────────────────────────────────────────────┐
│ 当前: dentry = "home" (在根文件系统中)                              │
│       vfsmnt = mount_根.mnt                                        │
│       mnt = mount_根                                               │
│                                                                    │
│ 检查1: 否                                                          │
│ 检查2: "home" != "/" (根文件系统根) → 否                           │
│                                                                    │
│ 操作: prepend_name("home")                                         │
│       缓冲区: [                     /home/user/test.txt]           │
│       dentry = d_parent = "/" (根文件系统的根)                      │
│                                                                    │
│ 返回 0 (继续迭代)                                                   │
└────────────────────────────────────────────────────────────────────┘

第 5 次 cwd_read():  ★ 到达终点 ★
┌────────────────────────────────────────────────────────────────────┐
│ 当前: dentry = "/" (根文件系统的根)                                 │
│       vfsmnt = mount_根.mnt                                        │
│       mnt = mount_根                                               │
│                                                                    │
│ 检查1: dentry == root_dentry && vfsmnt == root_mnt?                │
│        "/" == 进程根 && mount_根 == 进程根挂载 → 是！               │
│                                                                    │
│ 设置 data.resolved = true                                          │
│ 返回 1 (结束迭代)                                                   │
└─────────────────���──────────────────────────────────────────────────┘
```

### 最终结果

```
缓冲区: [                          /home/user/test.txt]
                                   ^
                                   |
                               返回指针

路径长度 = 初始 4096 - 剩余空间 = 20 字节
```

---

## 4. 核心代码详解

### cwd_read 中的挂载点处理代码

```c
FUNC_INLINE long cwd_read(struct cwd_read_data *data)
{
    // ... 变量定义 ...

    // ========== 检查1: 是否到达进程根目录？ ==========
    if (!(dentry != data->root_dentry || vfsmnt != data->root_mnt)) {
        data->resolved = true;
        return 1;  // 完成
    }

    // ========== 检查2: 是否到达当前文件系统边界？ ==========
    // 读取当前挂载点的根 dentry
    probe_read(&vfsmnt_mnt_root, sizeof(vfsmnt_mnt_root),
               _(&vfsmnt->mnt_root));

    // 两种情况表示到达文件系统边界:
    // 1. dentry == mnt_root: 当前 dentry 是挂载点的根
    // 2. IS_ROOT(dentry): dentry->d_parent == dentry (根目录特征)
    if (dentry == vfsmnt_mnt_root || IS_ROOT(dentry)) {
        struct mount *parent;

        // 获取父挂载点
        probe_read(&parent, sizeof(parent), _(&mnt->mnt_parent));

        // ===== 检查是否为全局根 =====
        // 如果 mnt == parent，说明没有父挂载点，已经是全局根
        if (data->mnt != parent) {
            // ===== 跨挂载点跳转 =====
            // 1. 获取当前挂载点在父文件系统中的 dentry
            //    这就是挂载点的"另一面"
            probe_read(&data->dentry, sizeof(data->dentry),
                       _(&mnt->mnt_mountpoint));

            // 2. 切换到父挂载点
            data->mnt = parent;
            data->vfsmnt = _(&parent->mnt);

            // 3. 继续迭代（注意：本次没有写入缓冲区！）
            return 0;
        }

        // 到达全局根，解析完成
        data->resolved = true;
        return 1;
    }

    // ========== 正常情况：处理当前目录项 ==========
    // ... prepend_name 等操作 ...
}
```

---

## 5. 挂载点处理的关键点

### 关键点 1: mnt_mountpoint 的作用

```
mnt_mountpoint 是跨挂载点的"桥梁"

                    根文件系统                  home 文件系统
                    ┌─────────┐                ┌─────────┐
                    │   "/"   │                │   "/"   │ ← mnt_root
                    └────┬────┘                └────┬────┘
                         │                          │
                    ┌────┴────┐                ┌────┴────┐
mnt_mountpoint ───→ │ "home"  │ ←─── 挂载点 ───→│ "user"  │
                    │ "etc"   │                └────┬────┘
                    └─────────┘                     │
                                              ┌─────┴─────┐
                                              │"test.txt" │
                                              └───────────┘

遍历到 home 文件系统的 "/" 时:
  → 通过 mnt_mountpoint 获取 "home" dentry
  → 切换到根文件系统继续遍历
```

### 关键点 2: 为什么 IS_ROOT 检查？

```c
FUNC_INLINE bool IS_ROOT(struct dentry *dentry)
{
    struct dentry *d_parent;
    probe_read(&d_parent, sizeof(d_parent), _(&dentry->d_parent));
    return (dentry == d_parent);  // 根目录的 d_parent 指向自己
}
```

**为什么需要这个检查？**

某些情况下，`dentry == mnt_root` 检查不够：
- 伪文件系统（如 procfs、sysfs）
- 某些特殊挂载

`IS_ROOT` 是一个额外的安全检查。

### 关键点 3: 全局根的判断

```c
if (data->mnt != parent) {
    // 有父挂载点，跨越继续
} else {
    // mnt == parent，说明是全局根
    // 根文件系统的 mnt_parent 指向自己
    data->resolved = true;
    return 1;
}
```

---

## 6. 复杂场景：多层挂载

```
场景: /a/b/c/d/file.txt
其中 /a, /a/b, /a/b/c 各自挂载了不同分区

目录树:
/              ← 根文件系统
└── a          ← 挂载点1
    └── b      ← 挂载点2
        └── c  ← 挂载点3
            └── d
                └── file.txt

挂载关系:
mount_根 ← mount_a ← mount_b ← mount_c

遍历过程:
1. file.txt → prepend "/file.txt"
2. d        → prepend "/d"
3. c (mnt_root) → 跨到 mount_b, dentry="c"
4. c        → prepend "/c"
5. b (mnt_root) → 跨到 mount_a, dentry="b"
6. b        → prepend "/b"
7. a (mnt_root) → 跨到 mount_根, dentry="a"
8. a        → prepend "/a"
9. / (root_dentry) → 完成

最终: /a/b/c/d/file.txt
```

---

## 7. 特殊情况处理

### 情况 1: 已删除文件

```c
// path_with_deleted 函数
if (d_unlinked(dentry)) {
    prepend(buf, buflen, " (deleted)", 10);
}
```

结果示例：`/tmp/test.txt (deleted)`

### 情况 2: 路径太深

```c
// 如果迭代次数耗尽但还没到达根
if (!data.resolved)
    error = UNRESOLVED_PATH_COMPONENTS;
```

这时返回的路径是**部分路径**，调用者需要检查 error 标志。

### 情况 3: chroot 环境

```c
// __d_path_local 使用进程的 fs->root 作为终点
task = (struct task_struct *)get_current_task();
probe_read(&fs, sizeof(fs), _(&task->fs));
*error = path_with_deleted(path, _(&fs->root), ...);
```

chroot 进程看到的路径以 chroot 目录为根，确保路径隔离。

---

## 8. 本章总结

```
┌─────────────────────────────────────────────────────────────────────┐
│                    挂载点处理核心逻辑                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 每次迭代检查是否到达 mnt_root 或 IS_ROOT                        │
│                                                                     │
│  2. 如果是，检查是否有父挂载点 (mnt != mnt_parent)                   │
│                                                                     │
│  3. 如果有父挂载点:                                                  │
│     - 通过 mnt_mountpoint 获取挂载点 dentry                         │
│     - 切换到父挂载点                                                 │
│     - 继续迭代（本次不写缓冲区）                                     │
│                                                                     │
│  4. 如果没有父挂载点:                                                │
│     - 已经是全局根，解析完成                                         │
│                                                                     │
│  关键结构:                                                          │
│    mount.mnt_parent     → 父挂载点                                  │
│    mount.mnt_mountpoint → 挂载点在父文件系统中的 dentry              │
│    vfsmount.mnt_root    → 当前文件系统的根 dentry                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. 完整遍历流程图

```
                          开始
                            │
                            ▼
              ┌─────────────────────────────┐
              │  获取缓冲区 (percpu map)    │
              └─────────────┬───────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │  初始化: res = buf + 4096   │
              │  (从缓冲区末尾开始)          │
              └─────────────┬───────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │  获取进程根目录 fs->root    │
              └─────────────┬───────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │  检查文件是否已删除         │
              │  是则追加 " (deleted)"      │
              └─────────────┬───────────────┘
                            │
          ┌─────────────────┴─────────────────┐
          │           循环开始                 │
          │  (最多 11/128/2048 次迭代)        │
          └─────────────────┬─────────────────┘
                            │
          ┌─────────────────▼─────────────────┐
          │  dentry == root && mnt == root?   │
          └─────────────────┬─────────────────┘
                    是      │      否
          ┌─────────────────┘      │
          │                        ▼
          │         ┌──────────────────────────┐
          │         │ dentry == mnt_root       │
          │         │ 或 IS_ROOT(dentry)?      │
          │         └──────────────┬───────────┘
          │                 是     │     否
          │         ┌──────────────┘     │
          │         │                    │
          │         ▼                    │
          │  ┌──────────────────┐        │
          │  │ mnt != parent?   │        │
          │  └────────┬─────────┘        │
          │      是   │   否             │
          │  ┌────────┘   │              │
          │  │            │              │
          │  ▼            │              ▼
          │ ┌────────────┐│    ┌─────────────────────┐
          │ │跨挂载点:   ││    │ prepend_name()      │
          │ │dentry=     ││    │ 插入 "/" + 目录名   │
          │ │mountpoint  ││    │ dentry = d_parent   │
          │ │mnt=parent  ││    └──────────┬──────────┘
          │ │继续循环    ││               │
          │ └────────────┘│               │
          │       │       │               │
          │       │       ▼               │
          │       │  ┌────────────┐       │
          │       │  │ 全局根     │       │
          │       │  │ resolved=  │       │
          │       │  │ true       │       │
          │       │  └─────┬──────┘       │
          │       │        │              │
          └───────┴────────┴──────────────┘
                           │
                           ▼
              ┌─────────────────────────────┐
              │  计算路径长度               │
              │  buflen = 4096 - 剩余空间   │
              └─────────────┬───────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │  返回路径指针 res           │
              └─────────────────────────────┘
```

---

## 参考资料

- Linux 内核 d_path 实现: https://elixir.bootlin.com/linux/v5.10/source/fs/d_path.c#L262
- Linux VFS 文档: https://www.kernel.org/doc/html/latest/filesystems/vfs.html
- Tetragon 项目: https://github.com/cilium/tetragon
