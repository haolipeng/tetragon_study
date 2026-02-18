# d_path_local 函数深度分析

本文档系列深入分析 Tetragon 项目中 `d_path_local` 函数的实现原理，解析它如何在 eBPF 上下文中获取进程的完整文件路径。

## 文档结构

| 文档 | 内容 | 适合读者 |
|-----|------|---------|
| [01-基础概念.md](01-基础概念.md) | Linux VFS、dentry、mount、path 核心概念 | 入门者必读 |
| [02-核心算法.md](02-核心算法.md) | 逆向遍历算法、函数调用链、逐行代码注释 | 理解实现原理 |
| [03-eBPF限制与方案.md](03-eBPF限制与方案.md) | eBPF 限制及 Tetragon 的解决方案 | eBPF 开发者 |
| [04-挂载点处理.md](04-挂载点处理.md) | 跨挂载点路径解析的详细机制 | 深入理解者 |

## 核心源文件

```
/home/work/tetragon_study/bpf/lib/bpf_d_path.h    # 主实现文件
```

## 函数调用关系

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
                    │
                    └─→ prepend_path() ← 核心：路径遍历
                            │
                            └─→ cwd_read()    ← 循环调用，每次处理一级目录
                                    │
                                    └─→ prepend_name() ← 插入目录名到缓冲区
```

## 核心原理概述

### 逆向遍历

从目标文件的 dentry 出发，通过 `d_parent` 指针逐级回溯到根目录，构建完整路径。

```
    /  ←─────────────────┐
    |                    │
  home ←─────────────┐   │ d_parent
    |                │   │
  user ←─────────┐   │   │ d_parent
    |            │   │   │
test.txt ────────┴───┴───┘ 起点
```

### 缓冲区从末尾向前填充

```
初始:  [                                                ]
                                                        ^
第1步: [                                    /test.txt  ]
                                            ^
第2步: [                               /user/test.txt  ]
                                       ^
第3步: [                          /home/user/test.txt  ]
                                  ^
                               返回指针
```

### 跨挂载点处理

当遍历到达文件系统边界时，通过 `mnt_parent` 和 `mnt_mountpoint` 跳转到父挂载点继续遍历。

## 使用场景

1. **获取进程当前工作目录 (CWD)**
   - 文件: `bpf/process/bpf_process_event.h`
   - 函数: `getcwd()`

2. **获取可执行文件路径**
   - 文件: `bpf/lib/process.h`
   - 函数: `read_exe()`

3. **获取任意文件路径**
   - 文件: `bpf/process/types/basic.h`
   - 函数: `copy_path()`

## 技术亮点

| 挑战 | 解决方案 |
|-----|---------|
| 栈空间 512 字节限制 | 使用 percpu array map 存储 4KB 缓冲区 |
| 循环需有界 | 根据内核版本选择 unroll/bpf_loop/bpf_for |
| 内存访问需验证 | 使用 probe_read + 边界检查 |
| 跨内核版本兼容 | BTF + CO-RE 技术 |

## 参考资料

- Linux 内核 d_path 实现: https://elixir.bootlin.com/linux/v5.10/source/fs/d_path.c#L262
- Tetragon 项目: https://github.com/cilium/tetragon
