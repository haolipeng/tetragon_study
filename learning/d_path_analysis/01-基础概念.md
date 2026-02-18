# Linux 文件系统基础概念

本文档介绍理解 `d_path_local` 所必需的 Linux 文件系统核心概念。

---

## 1. VFS（虚拟文件系统）概述

### 什么是 VFS？

VFS 是 Linux 内核中的抽象层，为上层应用提供统一的文件操作接口，屏蔽底层不同文件系统（ext4、xfs、ntfs、nfs 等）的实现差异。

```
┌─────────────────────────────────────────────────────────────┐
│                      用户空间                                │
│   应用程序: open(), read(), write(), close() ...            │
└─────────────────────────┬───────────────────────────────────┘
                          │ 系统调用
┌─────────────────────────▼───────────────────────────────────┐
│                      VFS 层                                  │
│   提供统一的文件操作抽象接口                                   │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  核心对象: superblock, inode, dentry, file          │   │
│   └─────────────────────────────────────────────────────┘   │
└───────┬─────────────────┬─────────────────┬─────────────────┘
        │                 │                 │
┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐
│     ext4      │ │      xfs      │ │      nfs      │
│   文件系统     │ │    文件系统    │ │    文件系统    │
└───────────────┘ └───────────────┘ └───────────────┘
```

### VFS 的四大核心对象

| 对象 | 作用 | 对应的结构体 |
|-----|------|------------|
| **superblock** | 描述整个文件系统的元信息 | `struct super_block` |
| **inode** | 描述单个文件的元数据（权限、大小、时间戳等） | `struct inode` |
| **dentry** | 目录项，将文件名映射到 inode | `struct dentry` |
| **file** | 进程打开的文件实例 | `struct file` |

---

## 2. dentry（目录项）详解

### dentry 是什么？

**dentry** 是 "directory entry"（目录项）的缩写，是 VFS 中最关键的概念之一。

**核心作用**：将**文件名**（路径组件）映射到对应的 **inode**。

举个例子，对于路径 `/home/user/test.txt`：

```
路径: /home/user/test.txt

这个路径包含 4 个路径组件，对应 4 个 dentry:

  "/"          →  dentry_1  →  inode_根目录
  "home"       →  dentry_2  →  inode_home目录
  "user"       →  dentry_3  →  inode_user目录
  "test.txt"   →  dentry_4  →  inode_test.txt文件
```

### dentry 的核心字段

```c
struct dentry {
    struct dentry      *d_parent;   // 父目录的 dentry（关键！用于回溯路径）
    struct qstr         d_name;     // 目录项名称（如 "home", "user"）
    struct inode       *d_inode;    // 指向对应的 inode
    struct list_head    d_child;    // 兄弟节点链表
    struct list_head    d_subdirs;  // 子目录链表
    unsigned int        d_flags;    // 状态标志
    // ... 其他字段
};

struct qstr {                       // 快速字符串结构
    const unsigned char *name;      // 名称指针
    unsigned int         len;       // 名称长度
};
```

### dentry 链表结构图

```
         根目录 "/"
         ┌──────────┐
         │  dentry  │  d_name = "/"
         │──────────│
         │ d_parent │ ──→ 指向自己（根目录特征）
         │ d_inode  │ ──→ inode_根
         └────┬─────┘
              │ d_subdirs
              ▼
    ┌─────────────────────────┐
    │                         │
┌───▼──────┐            ┌─────▼────┐
│  dentry  │            │  dentry  │
│──────────│            │──────────│
│  "home"  │            │  "etc"   │
│ d_parent │──→ "/"     │ d_parent │──→ "/"
└────┬─────┘            └──────────┘
     │ d_subdirs
     ▼
┌──────────┐
│  dentry  │
│──────────│
│  "user"  │
│ d_parent │──→ "home"
└────┬─────┘
     │ d_subdirs
     ▼
┌──────────┐
│  dentry  │
│──────────│
│"test.txt"│
│ d_parent │──→ "user"
└──────────┘
```

### 关键点：d_parent 字段

**`d_parent`** 字段指向父目录的 dentry，这是 `d_path_local` 能够回溯路径的关键！

从任意文件的 dentry 出发，不断访问 `d_parent`，就能一路回溯到根目录 `/`，从而构建完整路径。

---

## 3. mount（挂载点）概念

### 为什么需要 mount？

Linux 采用**单一目录树**结构，所有文件系统都挂载到同一棵目录树上。例如：

```
/                      ← 根文件系统 (ext4)
├── home               ← 可能是单独的分区 (ext4)
├── boot               ← 引导分区 (vfat)
├── proc               ← 虚拟文件系统 (procfs)
├── sys                ← 虚拟文件系统 (sysfs)
└── mnt
    └── usb            ← U盘 (ntfs)
```

每个挂载点都有对应的 `mount` 结构体来描述。

### mount 相关结构体

```c
// 挂载点结构（精简版）
struct mount {
    struct mount       *mnt_parent;     // 父挂载点
    struct dentry      *mnt_mountpoint; // 挂载点在父文件系统中的 dentry
    struct vfsmount     mnt;            // 内嵌的 vfsmount 结构
    // ...
};

// vfsmount 是对外暴露的挂载信息
struct vfsmount {
    struct dentry      *mnt_root;       // 此文件系统的根 dentry
    struct super_block *mnt_sb;         // 超级块
    int                 mnt_flags;      // 挂载标志
};
```

### 挂载点层次结构图

```
假设 /home 是单独的分区挂载:

根文件系统 (/)                     /home 文件系统
┌─────────────────┐               ┌─────────────────┐
│   mount_根      │               │   mount_home    │
│─────────────────│               │─────────────────│
│ mnt_parent  ────┼─→ 自己        │ mnt_parent  ────┼─→ mount_根
│ mnt_mountpoint  │ (无)          │ mnt_mountpoint ─┼─→ dentry("home")
│     ↓           │               │     ↓           │
│ mnt.mnt_root ───┼─→ dentry("/") │ mnt.mnt_root ───┼─→ dentry_home_根
└─────────────────┘               └─────────────────┘

访问 /home/user 的路径解析:
1. 从 /home/user 的 dentry 开始
2. 回溯到 /home 文件系统的根 dentry
3. 发现到达 mnt_root，需要跨越挂载点
4. 通过 mnt_parent 找到父挂载点
5. 通过 mnt_mountpoint 找到 "home" 在父文件系统中的位置
6. 继续回溯直到根目录 "/"
```

### 关键点：跨挂载点路径解析

当路径跨越多个挂载点时，`d_path_local` 必须：
1. 检测是否到达当前文件系统的根（`mnt_root`）
2. 如果是，通过 `mnt_parent` 跳转到父挂载点
3. 使用 `mnt_mountpoint` 获取挂载点在父文件系统中的 dentry
4. 继续回溯

---

## 4. struct path 结构

### path 的定义

```c
struct path {
    struct vfsmount *mnt;     // 所在的挂载点
    struct dentry   *dentry;  // 目录项
};
```

**`struct path`** 是一个简单但重要的结构，它将 **挂载点信息** 和 **目录项** 组合在一起，完整描述了文件在整个目录树中的位置。

### 为什么需要同时有 mnt 和 dentry？

**原因**：同一个 dentry 可能出现在不同的挂载点下（比如 bind mount）。

```
例如: mount --bind /home/user /mnt/backup

/home/user/file.txt  →  path1: { mnt=mount_home, dentry=dentry_file }
/mnt/backup/file.txt →  path2: { mnt=mount_backup, dentry=dentry_file }

同一个 dentry_file，但属于不同的 path!
```

### path 在进程中的位置

```c
struct task_struct {          // 进程描述符
    // ...
    struct fs_struct *fs;     // 文件系统信息
    // ...
};

struct fs_struct {
    struct path root;         // 进程的根目录 (chroot 会改变它)
    struct path pwd;          // 进程的当前工作目录
    // ...
};

struct file {                 // 打开的文件
    struct path f_path;       // 文件路径
    // ...
};
```

---

## 5. 概念总结

| 概念 | 核心作用 | d_path_local 如何使用 |
|-----|---------|---------------------|
| **dentry** | 目录项，文件名→inode 的映射 | 通过 `d_parent` 逐级回溯 |
| **d_name** | 存储目录项名称 | 获取每级目录名，拼接路径 |
| **mount** | 描述文件系统挂载关系 | 跨挂载点时跳转到父挂载点 |
| **vfsmount** | 挂载点的根 dentry | 判断是否到达挂载点边界 |
| **path** | dentry + vfsmount 组合 | 函数入参，起始解析点 |

---

## 下一步

理解这些基础概念后，继续阅读 [02-核心算法.md](02-核心算法.md) 了解具体实现。
