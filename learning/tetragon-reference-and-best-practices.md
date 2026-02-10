# Tetragon 关键文件索引、测试方法与性能优化

## 目录

- [第一部分：关键文件和函数索引](#第一部分关键文件和函数索引)
- [第二部分：验证和测试方法](#第二部分验证和测试方法)
- [第三部分：性能优化和最佳实践](#第三部分性能优化和最佳实践)
- [第四部分：常见问题和解决方案](#第四部分常见问题和解决方案)
- [第五部分：扩展阅读和参考资料](#第五部分扩展阅读和参考资料)

---

## 第一部分：关键文件和函数索引

### 1.1 eBPF 内核层文件

| 文件路径 | 功能 | 关键函数/宏 |
|---------|------|-----------|
| `bpf/process/bpf_execve_bprm_commit_creds.c` | Setuid/setgid/文件能力检测 | `tg_kp_bprm_committing_creds()` |
| `bpf/lib/bpf_cred.h` | 凭证和能力数据结构 | `msg_capabilities`, `msg_cred`, `__cap_gained()`, `__cap_issubset()` |
| `bpf/process/bpf_process_event.h` | 进程事件和凭证读取 | `__get_caps()`, `get_current_subj_caps()`, `get_current_subj_creds()` |
| `bpf/lib/process.h` | 进程相关 Maps | `execve_map`, `tg_execve_joined_info_map`, `execve_heap` |
| `bpf/process/bpf_generic_kprobe.c` | 通用 kprobe 框架 | `generic_kprobe_event()`, `generic_kprobe_filter_arg()` |
| `bpf/process/bpf_generic_lsm_core.c` | 通用 LSM 框架 | `generic_lsm_event()`, tail call pipeline |
| `bpf/process/generic_calls.h` | Tail call 辅助函数 | `tail_call()` 封装 |
| `bpf/process/types/basic.h` | 基础类型和枚举 | `TAIL_CALL_*` 枚举, `EXEC_*` 标志, `get_path()`, `store_path()` |
| `bpf/process/types/operations.h` | 操作类型 | `op_capabilities_gained` |
| `bpf/process/generic_maps.h` | 通用 Maps 定义 | `kprobe_calls`, `lsm_calls` |
| `bpf/lib/bpf_d_path.h` | 路径解析（dentry walking） | `d_path_local()`, `prepend_path()`, `cwd_read()`, `prepend_name()` |
| `bpf/process/generic_path.h` | 路径卸载机制 | `path_init()`, `path_work()`, `should_offload_path()` |
| `bpf/process/bpf_generic_lsm_ima_file.c` | IMA Hash 支持 | `BPF_PROG(ima_file)` |

### 1.2 Go ��用层文件

| 文件路径 | 功能 | 关键函数/类型 |
|---------|------|-------------|
| `pkg/sensors/load_linux.go` | BPF 加载 | `loadMap()`, `observerLoadInstance()`, `preLoadMaps()` |
| `pkg/observer/observer_linux.go` | 事件读取 | `RunEvents()`, ring/perf buffer 处理 |
| `pkg/observer/observer.go` | 事件分发 | `receiveEvent()`, `HandlePerfData()`, `eventHandler` map |
| `pkg/sensors/tracing/generickprobe.go` | Kprobe 事件处理 | `handleGenericKprobe()`, `genericKprobe` 结构体, `addKprobe()` |
| `pkg/sensors/tracing/args_linux.go` | 参数解析 | `getArg()`, `parseString()`, `argPrinter` |
| `pkg/reader/caps/caps.go` | Capability 转换 | `GetCapabilitiesTypes()`, `GetMsgCapabilities()` |
| `pkg/selectors/kernel.go` | 选择器编译 | `capsStrToUint64()`, `writePrefix()`, `writePostfix()` |
| `pkg/generictypes/generictypes.go` | 类型常量和映射 | `GenericFileType`, `PathType()`, `GenericTypeFromString()` |
| `pkg/server/server.go` | gRPC 服务 | `GetEventsWG()`, `Server` 结构体 |
| `pkg/k8s/apis/cilium.io/v1alpha1/types.go` | TracingPolicy 类型 | `TracingPolicySpec`, `CapabilitiesSelector`, `KProbeSelector` |
| `api/v1/tetragon/capabilities.proto` | Capability Protobuf | `CapabilitiesType` enum, `Capabilities` message |
| `api/v1/tetragon/events.proto` | 事件 Protobuf | `GetEventsResponse`, `ProcessExec`, `ProcessKprobe` |
| `pkg/api/tracingapi/client_kprobe.go` | Kprobe 事件数据结构 | `MsgGenericKprobeArgFile`, `MsgGenericKprobeArgPath` |

### 1.3 示例 TracingPolicy 文件

| 文件路径 | 检测场景 |
|---------|---------|
| `examples/policylibrary/privileges/privileges-raise.yaml` | 综合提权检测（capset, setuid/setgid, user namespace） |
| `examples/policylibrary/privileges/privileges-setuid-root.yaml` | Setuid root 执行 |
| `examples/tracingpolicy/process-credentials/creds-capability-usage.yaml` | Capability 检查（cap_capable） |
| `examples/tracingpolicy/sys_setuid.yaml` | setuid 系统调用 |
| `examples/tracingpolicy/fd_install_caps.yaml` | 文件描述符安装（含 capabilities） |
| `examples/quickstart/file_monitoring.yaml` | 文件读写权限监控 |
| `examples/quickstart/file_monitoring_enforce.yaml` | 文件写入阻断 |
| `examples/tracingpolicy/filename_monitoring.yaml` | 文件名提取监控 |
| `examples/tracingpolicy/lsm_file_open.yaml` | LSM 级别文件打开 |
| `examples/tracingpolicy/fd_install_ns.yaml` | FD 安装 + 命名空间过滤 |

---

## 第二部分：验证和测试方法

### 2.1 环境搭建

```bash
# 1. 安装 Tetragon
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/install/kubernetes/tetragon.yaml

# 2. 安装 tetra CLI
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
curl -L -o tetra https://github.com/cilium/tetragon/releases/latest/download/tetra-${GOOS}-${GOARCH}
chmod +x tetra
sudo mv tetra /usr/local/bin/

# 3. 验证安装
tetra version
kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon
```

### 2.2 基础测试命令

```bash
# 实时查看所有事件
tetra getevents -o compact

# 仅查看提权相关事件
tetra getevents -o compact | grep -E "(SETUID|SETGID|CAP_)"

# JSON 格式输出（便于分析）
tetra getevents -o json | jq .

# 过滤特定进程
tetra getevents -o compact --process /usr/bin/sudo

# 过滤特定 capability
tetra getevents --caps CAP_SYS_ADMIN
```

### 2.3 完整测试流程

#### 测试1：验证 Setuid 检测

```bash
# 步骤1: 创建测试程序
cat > /tmp/test_setuid.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("UID: %d, EUID: %d\n", getuid(), geteuid());
    return 0;
}
EOF

gcc -o /tmp/test_setuid /tmp/test_setuid.c
sudo chown root:root /tmp/test_setuid
sudo chmod u+s /tmp/test_setuid

# 步骤2: 启动事件监控（另一终端）
tetra getevents -o json | jq 'select(.process_exec != null and .process_exec.process.binary_properties.privileges_changed != null)'

# 步骤3: 执行测试
/tmp/test_setuid

# 步骤4: 验证输出
# 应看到包含 "PRIVILEGES_RAISED_EXEC_FILE_SETUID" 的事件
```

#### 测试2：验证系统调用监控

```bash
# 步骤1: 应用 TracingPolicy
kubectl apply -f - << 'EOF'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: test-setuid-syscall
spec:
  kprobes:
  - call: "__sys_setuid"
    syscall: false
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "0"
EOF

# 步骤2: 监控事件
tetra getevents -o compact | grep setuid

# 步骤3: 触发（需要以 root 或有 CAP_SETUID 运行）
sudo python3 -c "import os; os.setuid(0); print('OK')"

# 步骤4: 清理
kubectl delete tracingpolicy test-setuid-syscall
```

#### 测试3：验证 Capability 监控

```bash
# 步骤1: 应用 TracingPolicy
kubectl apply -f examples/tracingpolicy/process-credentials/creds-capability-usage.yaml

# 步骤2: 监控
tetra getevents -o compact | grep cap_capable

# 步骤3: 触发（容器内执行需要 CAP_SYS_ADMIN 的操作）
kubectl run -it --rm debug --image=ubuntu:latest --restart=Never -- bash
# 在容器内:
mount -t tmpfs tmpfs /mnt  # 需要 CAP_SYS_ADMIN

# 步骤4: 观察事件
```

### 2.4 性能测试

```bash
# 测试1: 检查 BPF 程序开销
sudo bpftool prog show | grep tetragon
sudo bpftool prog dump xlated id <ID> | wc -l  # 指令数

# 测试2: 测量事件处理延迟
tetra getevents -o json | \
  jq -r '[.time, .process_exec.process.start_time] | @csv' | \
  awk -F, '{print ($1 - $2) * 1000 "ms"}'

# 测试3: Map 使用情况
sudo bpftool map list | grep tetragon
sudo bpftool map dump name execve_map | wc -l
```

### 2.5 故障排查

```bash
# 1. 检查 BPF 程序是否加载
sudo bpftool prog list | grep -E "(kprobe|lsm)" | grep tetragon

# 2. 检查 Maps
sudo bpftool map list | grep tetragon

# 3. 查看 Tetragon 日志
kubectl -n kube-system logs -l app.kubernetes.io/name=tetragon -f

# 4. 检查 TracingPolicy 状态
kubectl get tracingpolicy -A
kubectl describe tracingpolicy <name>

# 5. 验证内核版本支持
uname -r  # 需要 >= 4.19，推荐 5.10+
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF|CONFIG_KPROBES|CONFIG_TRACEPOINTS"
```

---

## 第三部分：性能优化和最佳实践

### 3.1 BPF 程序优化

#### 3.1.1 减少指令数

```c
// ❌ 避免：不必要的循环
for (int i = 0; i < 100; i++) {
    // ...
}

// ✅ 推荐：使用 bpf_for（配合 BPF Iterator）
#ifdef CONFIG_ITER_NUM
bpf_for(i, 0, 100) {
    // ...
}
#else
#pragma unroll
for (int i = 0; i < 10; i++) {  // 限制展开次数
    // ...
}
#endif
```

#### 3.1.2 优化 Map 访问

```c
// ❌ 避免：频繁查找同一 Map
struct value *v1 = bpf_map_lookup_elem(&map, &key);
// ... 100 行代码 ...
struct value *v2 = bpf_map_lookup_elem(&map, &key);  // 重复！

// ✅ 推荐：缓存查找结果
struct value *v = bpf_map_lookup_elem(&map, &key);
if (!v) return 0;
// 使用 v 多次
```

#### 3.1.3 提前返回

```c
// ✅ 尽早过滤
if (!should_trace(pid))
    return 0;  // 避免后续处理

// 继续复杂逻辑...
```

### 3.2 TracingPolicy 优化

#### 3.2.1 精确过滤

```yaml
# ❌ 避免：过于宽泛
kprobes:
- call: "sys_*"  # 会匹配所有系统调用！

# ✅ 推荐：精确匹配
kprobes:
- call: "__sys_setuid"
- call: "__sys_setgid"
```

#### 3.2.2 使用 Rate Limiting

```yaml
selectors:
- matchActions:
  - action: Post
    rateLimit: "1m"  # 每分钟最多 1 条相同事件
    rateLimitScope: "process"  # 限制作用域
```

#### 3.2.3 命名空间过滤

```yaml
# 只监控容器内进程
selectors:
- matchNamespaces:
  - namespace: Pid
    operator: NotIn
    values:
    - "host_ns"
```

### 3.3 系统级优化

#### 3.3.1 Ring Buffer 大小调整

```yaml
# Tetragon DaemonSet 配置
args:
  - --bpf-events-buffer-size=8192  # 增大 buffer（默认 4096）
```

#### 3.3.2 减少 CPU 开销

```bash
# 检查 perf overhead
sudo perf stat -e bpf:bpf_prog_load,bpf:bpf_map_update_elem \
  -a sleep 10

# 调整 BPF JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

---

## 第四部分：常见问题和解决方案

### 4.1 为什么某些提权未被检测？

**可能原因：**
1. **内核版本不支持 Hook 点**
   - 解决：检查 `cat /proc/kallsyms | grep security_bprm_committing_creds`

2. **User Namespace 内的 UID 映射**
   - Tetragon 当前不检测 user namespace 内的 uid=0 映射
   - 解决：监控 `create_user_ns` 调用

3. **内核漏洞利用**
   - 绕过了常规的凭证设置流程
   - 解决：结合其他检测（如内存扫描、行为分析）

### 4.2 如何减少误报？

**策略：**

1. **白名单已知良性程序**
   ```yaml
   selectors:
   - matchBinaries:
     - operator: "NotIn"
       values:
       - "/usr/bin/sudo"
       - "/usr/bin/su"
   ```

2. **结合其他上下文**
   ```yaml
   # 只告警非预期的父进程
   selectors:
   - matchPIDs:
     - operator: "NotIn"
       values:
       - "ppid:1"  # systemd
   ```

3. **调整 Rate Limiting**
   ```yaml
   matchActions:
   - action: Post
     rateLimit: "1m"
     rateLimitScope: "process"
   ```

### 4.3 性能影响评估

**测试方法：**
```bash
# 基准测试（无 Tetragon）
sysbench --test=cpu --max-time=60 run

# 启用 Tetragon 后
kubectl apply -f tetragon.yaml
sysbench --test=cpu --max-time=60 run

# 对比 CPU 使用率
top -b -n 1 | grep tetragon
```

**预期影响：**
- CPU: < 5% 增加（取决于监控的 kprobe 数量）
- 内存: ~ 100-500 MB（取决于 Map 大小和进程数）
- 延迟: < 1ms（事件处理）

### 4.4 文件监控特定问题

#### 路径解析不完整

**现象：** 事件中路径显示为 `/...` 或被截断

**原因：** dentry 遍历达到迭代上限

**解决：**
- 确认使用内核 >= 5.10（支持更多迭代次数）
- 检查 `flags` 字段是否包含 `UNRESOLVED_PATH_COMPONENTS`
- 考虑使用 `fd_install` 跟踪替代直接路径解析

#### Prefix/Postfix 匹配限制

- Prefix 最大长度：256 字符
- Postfix 最大长度：127 字符
- 超过限制的路径需要使用其他过滤方式

---

## 第五部分：扩展阅读和参考资料

### 5.1 核心概念

- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux Security Modules (LSM)](https://www.kernel.org/doc/html/latest/security/lsm.html)
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [BPF CO-RE (Compile Once, Run Everywhere)](https://nakryiko.com/posts/bpf-portability-and-co-re/)

### 5.2 Tetragon 官方资源

- [Tetragon GitHub](https://github.com/cilium/tetragon)
- [Tetragon Documentation](https://tetragon.io/)
- [TracingPolicy Examples](https://github.com/cilium/tetragon/tree/main/examples)

### 5.3 相关工具和项目

- **Falco**: 运行时安全（基于 eBPF 和内核模块）
- **Tracee**: Aqua Security 的 eBPF 追踪工具
- **BCC (BPF Compiler Collection)**: eBPF 工具集合
- **libbpf**: 标准 BPF 库

---

**文档版本：** v1.0
**更新日期：** 2026-02-09
**适用 Tetragon 版本：** v1.2+
