# Tetragon 文件系统监控深度分析

## 目录

- [第一部分：文件监控架构概览](#第一部分文件监控架构概览)
- [第二部分：eBPF 内核层文件监控实现](#第二部分ebpf-内核层文件监控实现)
- [第三部分：路径解析机制（Dentry Walking）](#第三部分路径解析机制dentry-walking)
- [第四部分：Go 应用层文件事件处理](#第四部分go-应用层文件事件处理)
- [第五部分：文件路径选择器（Prefix/Postfix 匹配）](#第五部分文件路径选择器prefixpostfix-匹配)
- [第六部分：完整数据流分析](#第六部分完整数据流分析)
- [第七部分：TracingPolicy 文件监控实战](#第七部分tracingpolicy-文件监控实战)

---

## 第一部分：文件监控架构概览

### 1.1 文件监控 Hook 点

| Hook 名称 | 参数类型 | 作用 |
|---------|---------|------|
| `security_file_permission` | `file` (struct file *) | 监控文件读/写权限检查 |
| `security_mmap_file` | `file` (struct file *) | 监控内存映射操作 |
| `security_path_truncate` | `path` (struct path *) | 监控文件截断操作 |
| `fd_install` | `file` (struct file *) | 监控文件描述符安装 |
| `file_open` (LSM) | `file` (struct file *) | LSM 级别文件打开监控 |
| `security_sb_mount` | `path` + `string` | 监控挂载操作 |

### 1.2 文件相关参数类型

```c
// bpf/process/types/basic.h (行 34-101)
enum {
    filename_ty = 14,        // 文件名 (struct filename *)
    path_ty = 15,            // 路径结构体 (struct path *)
    file_ty = 16,            // struct file *
    fd_ty = 17,              // 文件描述符 (int)
    kiocb_type = 24,         // 异步 I/O 控制块
    linux_binprm_type = 37,  // struct linux_binprm *
    dentry_type = 42,        // struct dentry *
};
```

### 1.3 文件监控数据流概览

```
┌──────────────────────────────────────────────────────────┐
│  TracingPolicy YAML                                      │
│  - call: "security_file_permission"                      │
│  - args: [{ index: 0, type: "file" }]                   │
│  - selectors: [matchArgs: { operator: "Prefix" }]       │
└──────────────┬──────────────────��────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────┐
│  BPF 内核层                                                │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ get_path() → 提取 struct path                       │ │
│  │ d_path_local() → dentry walking 解析路径             │ │
│  │ store_path() → 序列化为 [pathlen|path|flags|mode]   │ │
│  └──────────────────┬──────────────────────────────────┘ │
│                     │                                     │
│  ┌──────────────────▼──────────────────────────────────┐ │
│  │ Selector 过滤 (Prefix/Postfix LPM Trie 匹配)       │ │
│  └──────────────────┬──────────────────────────────────┘ │
│                     │                                     │
│  ┌──────────────────▼──────────────────────────────────┐ │
│  │ 写入 Ring/Perf Buffer                                │ │
│  └──────────────────┬──────────────────────────────────┘ │
└─────────────────────┼────────────────────────────────────┘
                      │
┌─────────────────────▼────────────────────────────────────┐
│  Go 用户空间                                               │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ getArg() → 解析 file/path/fd 类型参数               │ │
│  │ parseString() → 读取路径字符串                       │ │
│  │ → MsgGenericKprobeArgFile / ArgPath                 │ │
│  │ → Protobuf 序列化 → gRPC 发送                       │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

---

## 第二部分：eBPF 内核层文件监控实现

### 2.1 文件参数提取：get_path()

**文件：** `bpf/process/types/basic.h` (行 2535-2571)

```c
FUNC_INLINE const struct path *get_path(long type, unsigned long arg,
                                         struct path *path_buf)
{
    const struct path *path_arg = 0;
    struct kiocb *kiocb;
    struct file *file;

    switch (type) {
    case kiocb_type:
        // 从 kiocb->ki_filp 获取文件指针
        kiocb = (struct kiocb *)arg;
        arg = (unsigned long)_(&kiocb->ki_filp);
        probe_read(&file, sizeof(file), (const void *)arg);
        arg = (unsigned long)file;
        // fallthrough
    case file_ty:
        // 直接读取 struct file * 的 f_path 字段
        probe_read(&file, sizeof(file), &arg);
        path_arg = _(&file->f_path);
        break;
    case path_ty:
        // 直接使用传入的 struct path *
        probe_read(&path_arg, sizeof(path_arg), &arg);
        break;
    case dentry_type:
        // 从 dentry 创建临时 path 对象
        path_from_dentry((struct dentry *)arg, path_buf);
        path_arg = path_buf;
        break;
    case linux_binprm_type:
        // 从 bprm->file->f_path 获取
        struct linux_binprm *bprm = (struct linux_binprm *)arg;
        arg = (unsigned long)_(&bprm->file);
        probe_read(&file, sizeof(file), (const void *)arg);
        path_arg = _(&file->f_path);
        break;
    }
    return path_arg;
}
```

### 2.2 路径序列化：store_path()

**文件：** `bpf/process/types/basic.h` (行 380-408)

路径在 BPF 侧序列化为以下格式：

```
┌───────────┬──────────┬──────────┬─────────┐
│ 4 bytes   │ N bytes  │ 4 bytes  │ 2 bytes │
│ pathlen   │ path     │ flags    │ i_mode  │
└───────────┴──────────┴──────────┴─────────┘
```

```c
FUNC_INLINE long store_path(char *args, char *buffer,
                             const struct path *arg,
                             int size, int flags)
{
    // 写入路径长度
    probe_read(args, sizeof(int), &size);
    args += sizeof(int);

    // 写入路径字符串
    if (size > 0 && buffer)
        probe_read(args, size, buffer);
    args += size;

    // 写入标志位 (例如 UNRESOLVED_PATH_COMPONENTS)
    probe_read(args, sizeof(int), &flags);
    args += sizeof(int);

    // 写入 inode 模式 (权限位)
    __u16 i_mode;
    BPF_CORE_READ_INTO(&i_mode, arg, dentry, d_inode, i_mode);
    probe_read(args, sizeof(__u16), &i_mode);

    return size + sizeof(int) + sizeof(int) + sizeof(__u16);
}
```

### 2.3 文件描述符跟踪：fd_install

**文件：** `bpf/process/types/basic.h` (行 2195-2267)

#### 数据结构

```c
struct fdinstall_key {
    __u64 tid;        // 线程ID
    __u32 fd;         // 文件描述符
    __u32 pad;
};

struct fdinstall_value {
    char file[4104];  // 4096B 路径 + 4B 长度 + 4B 标志
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);  // 由 Agent 动态调整
    __type(key, struct fdinstall_key);
    __type(value, struct fdinstall_value);
} fdinstall_map SEC(".maps");
```

#### installfd() 函数

```c
FUNC_INLINE int
installfd(struct msg_generic_kprobe *e, int fd, int name, bool follow)
{
    struct fdinstall_key key = { 0 };

    key.tid = get_current_pid_tgid() >> 32;
    key.fd = *(__u32 *)&e->args[fdoff];

    if (follow) {
        // 存储文件路径数据到 fdinstall_map
        struct fdinstall_value *val;
        val = map_lookup_elem(&fdinstall_map, &key);
        if (!val) return 0;

        int size = *(int *)&e->args[nameoff];
        probe_read(&val->file[0], size + 4 + 4, &e->args[nameoff]);
        map_update_elem(&fdinstall_map, &key, val, BPF_ANY);
    } else {
        // 移除跟踪
        map_delete_elem(&fdinstall_map, &key);
    }
    return 0;
}
```

### 2.4 LSM Hook 框架

**文件：** `bpf/process/bpf_generic_lsm_core.c` (146 行)

```c
__attribute__((section("lsm/generic_lsm_core"), used)) int
generic_lsm_event(struct pt_regs *ctx)
{
    return generic_start_process_filter(ctx, &lsm_calls);
}

// LSM tail call 结构
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 13);
    __type(key, __u32);
    __array(values, int(void *));
} lsm_calls SEC(".maps") = {
    .values = {
        [TAIL_CALL_SETUP]   = (void *)&generic_lsm_setup_event,
        [TAIL_CALL_PROCESS] = (void *)&generic_lsm_process_event,
        [TAIL_CALL_FILTER]  = (void *)&generic_lsm_process_filter,
        [TAIL_CALL_ARGS]    = (void *)&generic_lsm_filter_arg,
        [TAIL_CALL_ACTIONS] = (void *)&generic_lsm_actions,
        [TAIL_CALL_PATH]    = (void *)&generic_lsm_path,
    },
};
```

### 2.5 IMA Hash 支持

**文件：** `bpf/process/bpf_generic_lsm_ima_file.c`

```c
__attribute__((section("lsm.s/generic_lsm_ima_file"), used)) int
BPF_PROG(ima_file, struct file *file)
{
    struct ima_hash hash;
    __u64 pid_tgid = get_current_pid_tgid();
    struct ima_hash *dummy = map_lookup_elem(&ima_hash_map, &pid_tgid);

    if (dummy && dummy->state == 1) {
        if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ima_file_hash))
            hash.algo = ima_file_hash(file, &hash.value, MAX_IMA_HASH_SIZE);
        else
            hash.algo = ima_inode_hash(file->f_inode, &hash.value,
                                       MAX_IMA_HASH_SIZE);
        hash.state = 2;
        map_update_elem(&ima_hash_map, &pid_tgid, &hash, BPF_ANY);
    }
    return 0;
}
```

---

## 第三部分：路径解析机制（Dentry Walking）

### 3.1 核心文件

**文件：** `bpf/lib/bpf_d_path.h` (353 行)

### 3.2 路径解析数据结构

```c
struct cwd_read_data {
    struct dentry *root_dentry;      // 根目录 dentry
    struct vfsmount *root_mnt;       // 根挂载点
    char *bf;                        // 缓冲区
    struct dentry *dentry;           // 当前 dentry
    struct vfsmount *vfsmnt;         // 当前挂载点
    struct mount *mnt;               // 实际挂载信息
    char *bptr;                      // 缓冲区指针
    int blen;                        // 缓冲区长度
    bool resolved;                   // 是否完全解析
};
```

### 3.3 关键函数分析

#### d_path_local() - 主入口

**行 336-352**

```c
FUNC_INLINE char *d_path_local(const struct path *path,
                                int *size, int *flags)
{
    // 从 buffer_heap_map 分配 4096 字节缓冲区
    char *buffer = map_lookup_elem(&buffer_heap_map, &zero);
    if (!buffer)
        return NULL;

    // 执行路径解析
    int err = __d_path_local(path, buffer, MAX_BUF_LEN, size);

    if (err)
        *flags |= UNRESOLVED_PATH_COMPONENTS;

    return buffer + MAX_BUF_LEN - *size;
}
```

#### __d_path_local() - 底层解析

**行 310-321**

```c
FUNC_INLINE int __d_path_local(const struct path *path,
                                char *buf, int buflen, int *size)
{
    // 读取根文件系统
    struct task_struct *task = get_current_task();
    struct fs_struct *fs;
    probe_read(&fs, sizeof(fs), _(&task->fs));

    struct path root;
    probe_read(&root, sizeof(root), _(&fs->root));

    // 调用 path_with_deleted 处理已删除文件
    return path_with_deleted(path, &root, buf, buflen, size);
}
```

#### prepend_path() - 核心 Dentry 遍历

**行 212-257**

```c
FUNC_INLINE int prepend_path(const struct path *path,
                              const struct path *root,
                              char *bf, int buflen, int *bufferlen)
{
    struct cwd_read_data data = {
        .root_dentry = root->dentry,
        .root_mnt = root->mnt,
        .bf = bf,
        .dentry = path->dentry,
        .vfsmnt = path->mnt,
        .mnt = real_mount(path->mnt),
        .bptr = bf + buflen,
        .blen = buflen,
        .resolved = false,
    };

    // 根据内核版本选择迭代次数
    // __V61_BPF_PROG: 2048 次
    // __LARGE_BPF_PROG: 128 次
    // 默认: 11 次
    for (int i = 0; i < PROBE_CWD_READ_ITERATIONS; i++) {
        if (cwd_read(&data))
            break;
    }

    *bufferlen = data.blen;
    return data.resolved ? 0 : -ENAMETOOLONG;
}
```

#### cwd_read() - 单次目录项读取

**行 156-203**

```c
FUNC_INLINE int cwd_read(struct cwd_read_data *data)
{
    // 1. 检查是否已到达根目录
    if (data->dentry == data->root_dentry &&
        data->vfsmnt == data->root_mnt) {
        data->resolved = true;
        return 1;  // 完成
    }

    // 2. 检查是否为根 dentry (IS_ROOT)
    struct dentry *parent;
    probe_read(&parent, sizeof(parent), _(&data->dentry->d_parent));

    if (data->dentry == parent) {
        // 3. 到达挂载点根目录，跨越挂载点
        struct mount *mnt_parent;
        probe_read(&mnt_parent, sizeof(mnt_parent),
                   _(&data->mnt->mnt_parent));

        if (data->mnt == mnt_parent) {
            // 全局根目录
            data->resolved = true;
            return 1;
        }

        // 切换到父挂载点
        probe_read(&data->dentry, sizeof(data->dentry),
                   _(&data->mnt->mnt_mountpoint));
        data->mnt = mnt_parent;
        data->vfsmnt = &mnt_parent->mnt;
        return 0;  // 继续
    }

    // 4. 读取当前 dentry 名称
    struct qstr d_name;
    probe_read(&d_name, sizeof(d_name), _(&data->dentry->d_name));

    // 5. 前置到缓冲区
    int error = prepend_name(data->bf, &data->bptr, &data->blen,
                              (const char *)d_name.name, d_name.len);

    // 6. 移动到父 dentry
    data->dentry = parent;

    return error ? 1 : 0;
}
```

#### prepend_name() - 名称前置

**行 112-154**

```c
FUNC_INLINE int prepend_name(char *buf, char **bufptr,
                               int *buflen,
                               const char *name, u32 namelen)
{
    // 限制名称长度为 255（Linux 最大文件名长度）
    asm volatile("%[namelen] &= 0xff;\n" : [namelen] "+r"(namelen));

    u64 buffer_offset = (u64)(*bufptr) - (u64)buf;
    int write_slash = 1;

    // 如果名称太长，截断
    if (namelen >= *buflen) {
        name += namelen - *buflen;
        namelen = *buflen;
        write_slash = 0;
    }

    *buflen -= namelen + write_slash;

    // 写入 '/' 分隔符
    if (write_slash) {
        buffer_offset -= 1;
        buf[buffer_offset & (MAX_BUF_LEN - 1)] = '/';
    }

    // 安全读取名称
    buffer_offset -= namelen;
    probe_read(buf + buffer_offset, namelen, name);

    *bufptr = buf + buffer_offset;

    return write_slash ? 0 : -ENAMETOOLONG;
}
```

### 3.4 路径卸载机制（Path Offloading）

**文件：** `bpf/process/generic_path.h` (234 行)

对于内核 v6.1+，路径解析使用 tail call 来突破 BPF 指令限制：

```
TAIL_CALL_PROCESS:
  generic_process_event
    generic_path_offload
      if type is path → tail_call TAIL_CALL_PATH

TAIL_CALL_PATH:
  generic_path
    path_init → 初始化状态机
      tail_call TAIL_CALL_PATH
    path_work → 执行 dentry 遍历
      if more work → tail_call TAIL_CALL_PATH
      if done → tail_call TAIL_CALL_PROCESS
```

#### 状态机定义

```c
enum {
    STATE_INIT,  // 初始状态 - 设置路径遍历
    STATE_WORK,  // 工作状态 - 迭代目录项
};

struct generic_path {
    int state;
    int off;                    // 缓冲区偏移
    int cnt;                    // 迭代计数
    struct path path_buf;
    const struct path *path;
    struct dentry *root_dentry;
    struct vfsmount *root_mnt;
    struct dentry *dentry;
    struct vfsmount *vfsmnt;
    struct mount *mnt;
};
```

#### path_work() 循环

```c
// 每次 tail call 执行的迭代次数
#ifdef __LARGE_BPF_PROG
#define GENERIC_PATH_ITERATIONS 512
#else
#define GENERIC_PATH_ITERATIONS 32
#endif

// 最多 8 次 tail call
#define GENERIC_PATH_MAX_CALLS 8
```

#### should_offload_path() 判断

```c
FUNC_INLINE bool should_offload_path(long ty)
{
    return ty == kiocb_type ||
           ty == file_ty ||
           ty == path_ty ||
           ty == dentry_type ||
           ty == linux_binprm_type;
}
```

---

## 第四部分：Go 应用层文件事件处理

### 4.1 类型常量定义

**文件：** `pkg/generictypes/generictypes.go` (行 13-75)

```go
const (
    GenericFilenameType = 14    // filename
    GenericPathType     = 15    // path
    GenericFileType     = 16    // file
    GenericFdType       = 17    // fd
    GenericKiocb        = 24    // kiocb
    GenericDentryType   = 42    // dentry
)
```

**字符串到类型映射（行 82-133）：**

```go
var genericStringToType = map[string]int{
    "file":     GenericFileType,      // 16
    "path":     GenericPathType,      // 15
    "fd":       GenericFdType,        // 17
    "dentry":   GenericDentryType,    // 42
    "filename": GenericFilenameType,  // 14
}
```

**路径类型判断（行 263-269）：**

```go
func PathType(ty int) bool {
    return ty == GenericPathType ||
        ty == GenericFileType ||
        ty == GenericDentryType ||
        ty == GenericLinuxBinprmType ||
        ty == GenericKiocb
}
```

### 4.2 文件事件数据结构

**文件：** `pkg/api/tracingapi/client_kprobe.go` (行 63-93)

```go
type MsgGenericKprobeArgFile struct {
    Index      uint64  // 参数索引 (0-5)
    Value      string  // 文件路径
    Flags      uint32  // 标志位
    Permission uint16  // inode 权限/模式 (如 0644)
    Label      string  // 参数标签
}

func (m MsgGenericKprobeArgFile) GetIndex() uint64 {
    return m.Index
}

func (m MsgGenericKprobeArgFile) IsReturnArg() bool {
    return (m.Index == ReturnArgIndex)  // Index 5 = return arg
}

type MsgGenericKprobeArgPath struct {
    Index      uint64  // 参数索引
    Value      string  // 路径字符串
    Flags      uint32  // 访问标志
    Permission uint16  // 模式/权限
    Label      string  // 参数标签
}
```

### 4.3 BPF 事件参数解析

**文件：** `pkg/sensors/tracing/args_linux.go` (行 126-198)

#### File 类型解析（行 126-168）

```go
case gt.GenericFileType, gt.GenericFdType, gt.GenericKiocb:
    var arg api.MsgGenericKprobeArgFile
    var flags uint32
    var b int32
    var mode uint16

    // 如果是 FD 类型，跳过 4 字节的文件描述符
    if a.ty == gt.GenericFdType {
        binary.Read(r, binary.LittleEndian, &b)
    }

    arg.Index = uint64(a.index)
    // 解析路径字符串
    arg.Value, err = parseString(r)  // 读取长度 + 路径

    // 读取标志位
    err := binary.Read(r, binary.LittleEndian, &flags)
    arg.Flags = flags

    // 如果是 file 或 kiocb，还要读取权限模式
    if a.ty == gt.GenericFileType || a.ty == gt.GenericKiocb {
        err := binary.Read(r, binary.LittleEndian, &mode)
        arg.Permission = mode
    }
    return arg
```

#### Path 类型解析（行 169-198）

```go
case gt.GenericPathType, gt.GenericDentryType:
    var arg api.MsgGenericKprobeArgPath
    var flags uint32
    var mode uint16

    arg.Index = uint64(a.index)
    arg.Value, err = parseString(r)      // 路径字符串

    err := binary.Read(r, binary.LittleEndian, &flags)
    arg.Flags = flags

    err = binary.Read(r, binary.LittleEndian, &mode)
    arg.Permission = mode

    return arg
```

#### 字符串解析函数（行 610-642）

```go
func parseString(r io.Reader) (string, error) {
    var size int32
    // 读取 4 字节的大小
    binary.Read(r, binary.LittleEndian, &size)

    if size < 0 || size > maxStringSize {
        return "", error
    }

    // 分配缓冲区
    stringBuffer := make([]byte, size)
    // 读取实际字符串
    binary.Read(r, binary.LittleEndian, &stringBuffer)

    // 移除尾部 null 字符
    if len(stringBuffer) > 0 && stringBuffer[len(stringBuffer)-1] == '\x00' {
        stringBuffer = stringBuffer[:len(stringBuffer)-1]
    }

    return strutils.UTF8FromBPFBytes(stringBuffer), nil
}
```

### 4.4 策略加载中的参数注册

**文件：** `pkg/sensors/tracing/generickprobe.go` (行 809-846)

```go
addArg := func(j int, a *v1alpha1.KProbeArg, data bool) error {
    var argType int
    userArgType := gt.GenericUserTypeFromString(a.Type)

    if userArgType != gt.GenericInvalidType {
        argType = gt.GenericUserToKernelType(userArgType)
    } else {
        // 解析类型字符串 ("file", "path", etc.) 为类型常量
        argType = gt.GenericTypeFromString(a.Type)
    }

    if argType == gt.GenericInvalidType {
        return fmt.Errorf("Arg(%d) type '%s' unsupported", j, a.Type)
    }

    eventConfig.ArgType[j] = int32(argType)
    argP := argPrinter{
        index:    int(a.Index),
        ty:       argType,
        userType: userArgType,
        label:    a.Label,
        data:     data,
    }
    argSigPrinters = append(argSigPrinters, argP)
    return nil
}
```

---

## 第五部分：文件路径选择器（Prefix/Postfix 匹配）

### 5.1 选择器操作符

**文件：** `pkg/selectors/kernel.go` (行 172-204)

```go
const (
    SelectorOpPrefix     = 8   // 匹配路径前缀
    SelectorOpPostfix    = 9   // 匹配路径后缀
    SelectorOpNotPrefix  = 26  // 排除路径前缀
    SelectorOpNotPostfix = 27  // 排除路径后缀
)
```

### 5.2 Prefix 匹配实现

**行 741-768**

使用 BPF LPM Trie（最长前缀匹配）实现高效路径前缀匹配：

```go
func writePrefix(k *KernelSelectorState, values []string,
                  selector string) (uint32, error) {
    mid, m := k.newStringPrefixMap()
    for _, v := range values {
        value, size := ArgSelectorValue(v)
        if size > StringPrefixMaxLength {  // 最大 256 字符
            return 0, fmt.Errorf("%s value %s invalid: string is longer than %d characters",
                selector, v, StringPrefixMaxLength)
        }
        // 创建 LPM trie 条目（前缀长度以位为单位）
        val := KernelLPMTrieStringPrefix{prefixLen: size * 8}
        copy(val.data[:], value)
        m[val] = struct{}{}
    }
    return mid, nil
}
```

### 5.3 Postfix 匹配实现

**行 770-806**

Postfix 匹配需要反转字符串，因为 BPF LPM Trie 只支持前缀匹配：

```go
func writePostfix(k *KernelSelectorState, values []string,
                   ty uint32, selector string) (uint32, error) {
    mid, m := k.newStringPostfixMap()
    for _, v := range values {
        var value []byte
        var size uint32
        if ty == gt.GenericCharBuffer {
            value, size = ArgPostfixSelectorValue(v, false)
        } else {
            value, size = ArgPostfixSelectorValue(v, true)
        }
        // BPF 反向拷贝限制，最大后缀 127 字符
        if size >= StringPostfixMaxLength {  // 最大 128 字符
            return 0, fmt.Errorf("%s value %s invalid: string is longer than %d characters",
                selector, v, StringPostfixMaxLength-1)
        }
        val := KernelLPMTrieStringPostfix{prefixLen: size * 8}
        // 反转拷贝后缀用于 LPM map
        for i := range value {
            val.data[len(value)-i-1] = value[i]
        }
        m[val] = struct{}{}
    }
    return mid, nil
}
```

### 5.4 LPM Trie 数据结构

```go
type KernelLPMTrieStringPrefix struct {
    prefixLen uint32
    data      [StringPrefixMaxLength]byte  // 最大 256 字节
}

type KernelLPMTrieStringPostfix struct {
    prefixLen uint32
    data      [StringPostfixMaxLength]byte  // 最大 128 字节
}

type KernelSelectorMaps struct {
    stringMaps        StringMapLists
    stringPrefixMaps  []map[KernelLPMTrieStringPrefix]struct{}   // 前缀 LPM tries
    stringPostfixMaps []map[KernelLPMTrieStringPostfix]struct{}  // 后缀 LPM tries
}
```

### 5.5 MatchArgs 路由逻辑

**行 909-926**

```go
case SelectorOpEQ, SelectorOpNEQ:
    switch ty {
    case gt.GenericFdType, gt.GenericFileType, gt.GenericPathType,
         gt.GenericStringType, gt.GenericCharBuffer, gt.GenericLinuxBinprmType,
         gt.GenericDataLoc, gt.GenericNetDev:
        err := writeMatchStrings(k, arg.Values, ty)  // 精确字符串匹配
        if err != nil {
            return fmt.Errorf("writeMatchStrings error: %w", err)
        }
    }
case SelectorOpPrefix, SelectorOpNotPrefix:
    err := writePrefixStrings(k, arg.Values)
    if err != nil {
        return fmt.Errorf("writePrefixStrings error: %w", err)
    }
case SelectorOpPostfix, SelectorOpNotPostfix:
    err := writePostfixStrings(k, arg.Values, ty)
    if err != nil {
        return fmt.Errorf("writePostfixStrings error: %w", err)
    }
```

---

## 第六部分：完整数据流分析

```
┌─────────────────────────────────────────────────────────┐
│  User Space (TracingPolicy YAML)                        │
│  - security_file_permission hook                        │
│  - file type argument @ index 0                         │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│  BPF 侧 (Kernel)                                         │
│  ┌────────────────────────────────────────────────────┐ │
│  │ get_path() 函数                                     │ │
│  │ - 提取 struct file -> struct path                 │ │
│  │ - 或直接接收 struct path *                         │ │
│  └────────────────┬─────────────────────────────────┘ │
│                   │                                    │
│  ┌────────────────▼─────────────────────────────────┐ │
│  │ generic_path_offload()                           │ │
│  │ - 尾调用到 TAIL_CALL_PATH                         │ │
│  └────────────────┬─────────────────────────────────┘ │
│                   │                                    │
│  ┌────────────────▼─────────────────────────────────┐ │
│  │ path_init() -> path_work() 循环                   │ │
│  │ - cwd_read() 迭代读取目录项                       │ │
│  │ - prepend_name() 前置目录名到缓冲区              │ │
│  │ - MAX 32 次迭代或 512 次部分迭代                 │ │
│  └────────────────┬─────────────────────────────────┘ │
│                   │                                    │
│  ┌────────────────▼─────────────────────────────────┐ │
│  │ store_path() 序列化                               │ │
│  │ - [4B] 路径长度                                   │ │
│  │ - [NB] 路径字符串                                 │ │
│  │ - [4B] 标志位 (UNRESOLVED_PATH_COMPONENTS)       │ │
│  │ - [2B] inode 模式                                 │ │
│  └────────────────┬─────────────────────────────────┘ │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│  Perf Ring Buffer                                       │
│  - 事件从内核传递到用户空间                             │
└──────────────────┬──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────┐
│  User Space (Go Runtime)                               │
│  ┌────────────────────────────────────────────────────┐ │
│  │ getArg() 在 args_linux.go (行 126-168)             │ │
│  │ - parseString() 读取文件路径                       │ │
│  │ - binary.Read() 读取 flags 和 permission          │ │
│  │ - 返回 MsgGenericKprobeArgFile                     │ │
│  └────────────────┬─────────────────────────────────┘ │
│                   │                                    │
│  ┌────────────────▼─────────────────────────────────┐ │
│  │ 事件序列化为 JSON/Protobuf                        │ │
│  │ - 输出到日志、gRPC 客户端等                       │ │
│  └────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

---

## 第七部分：TracingPolicy 文件监控实战

### 7.1 监控敏感文件读取

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sensitive-file-read"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"    # MAY_READ(4), MAY_WRITE(2)
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/boot"
        - "/root/.ssh"
        - "/etc/shadow"
        - "/etc/sudoers"
      - index: 1
        operator: "Equal"
        values:
        - "4"         # MAY_READ
```

### 7.2 监控内存映射操作

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "mmap-monitoring"
spec:
  kprobes:
  - call: "security_mmap_file"
    syscall: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "uint32"   # PROT_* flags
    - index: 2
      type: "uint32"   # MAP_* flags
```

### 7.3 监控文件描述符安装（含命名空间过滤）

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "fd-install"
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: int          # 文件描述符号
    - index: 1
      type: "file"       # struct file * 指针
    selectors:
    - matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"      # 排除宿主机命名空间
```

### 7.4 LSM 级别文件打开监控

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-file-open"
spec:
  lsm:
  - call: "file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/passwd"
        - "/etc/shadow"
```

### 7.5 综合文件监控（含执行阻断）

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring-enforce"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    selectors:
    # 监控：读取敏感文件
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/shadow"
        - "/root/.ssh"
      - index: 1
        operator: "Equal"
        values:
        - "4"
      matchActions:
      - action: Post
    # 阻断：写入系统关键文件
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/passwd"
        - "/etc/shadow"
        - "/etc/sudoers"
      - index: 1
        operator: "Equal"
        values:
        - "2"        # MAY_WRITE
      matchActions:
      - action: Sigkill   # 终止进程
```

---

## 关键文件位置总结

| 功能 | 文件路径 | 关键函数/行号 |
|------|---------|--------------|
| BPF 类型定义 | `bpf/process/types/basic.h` | 行 34-101 |
| fd_install 实现 | `bpf/process/types/basic.h` | `installfd()` 行 2212-2267 |
| path 获取 | `bpf/process/types/basic.h` | `get_path()` 行 2535-2571 |
| 路径存储格式 | `bpf/process/types/basic.h` | `store_path()` 行 380-408 |
| dentry → 路径 | `bpf/lib/bpf_d_path.h` | `cwd_read()` 行 156-203 |
| 名称前置 | `bpf/lib/bpf_d_path.h` | `prepend_name()` 行 112-154 |
| d_path 入口 | `bpf/lib/bpf_d_path.h` | `d_path_local()` 行 336-352 |
| 路径初始化 | `bpf/process/generic_path.h` | `path_init()` 行 29-67 |
| 路径工作循环 | `bpf/process/generic_path.h` | `path_work()` 行 77-117 |
| LSM 框架 | `bpf/process/bpf_generic_lsm_core.c` | `generic_lsm_event()` |
| IMA Hash | `bpf/process/bpf_generic_lsm_ima_file.c` | `BPF_PROG(ima_file)` |
| Go 类型定义 | `pkg/generictypes/generictypes.go` | 行 13-75 |
| Go 参数解析 | `pkg/sensors/tracing/args_linux.go` | `getArg()` 行 105-451 |
| 字符串解析 | `pkg/sensors/tracing/args_linux.go` | `parseString()` 行 610-642 |
| 事件 API | `pkg/api/tracingapi/client_kprobe.go` | 行 63-93 |
| 选择器编译 | `pkg/selectors/kernel.go` | `writePrefix/Postfix()` 行 741-806 |
| 策略加载 | `pkg/sensors/tracing/generickprobe.go` | `addKprobe()` 行 757-956 |

---

**文档版本：** v1.0
**更新日期：** 2026-02-09
**适用 Tetragon 版本：** v1.2+
