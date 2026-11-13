# Android Exit Tracer V2

通用 Android 进程退出 / 信号 / Native 崩溃 **原始日志采集器**。不包含 AI 分析、VM 检测、行为分类或报告生成。

## 实现

两个独立 ARM64 二进制：

- `exit-tracer`：Go / Android 主控，负责启动停止、日志轮换、logcat、进程/线程信息、tombstone 及回退
- `exit-tracer-ebpf`：Go / Linux 静态编译的 eBPF 加载器，内嵌 Clang 编译的 BPF ELF；从 perf event 接收内核事件并直接输出 JSONL

默认先尝试 eBPF，加载/附加失败或超时则自动启动 V1 的独立 tracefs instance；后者不修改其他 tracefs 实例或全局 tracer。

> 回退发生在 **启动阶段**。当前版本不会在 eBPF 运行过程中异常停止后自动切换；辅助进程错误可在 `ebpf.stderr.log` 和 `collector.log` 中发现。

## eBPF 捕获的数据

- `sched_process_exit`：线程退出事件（不代表每条都是整个进程死亡）
- `signal_generate` / `signal_deliver`：信号 4/5/6/7/8/9/11/15
- `raw_syscalls/sys_enter`（可选，当前 Pixel 6 已验证）：AArch64 的 `exit=93`、`exit_group=94`、`kill=129`、`tkill=130`、`tgkill=131`
- 在上述事件上尽可能调用 `bpf_get_stackid(..., BPF_F_USER_STACK)` 并导出 `user_stack_pc`（未经符号化的用户态 PC 数组）
- 原样记录 `user_stack_id`。负数（例如 `-14`）表示内核无法获取相应栈，**不代表没有调用者**。
- `sys_enter` 事件包含 syscall 编号、前 3 个参数（十六进制）及相关退出码/信号。
- perf ringbuffer 丢失事件时输出 `lost_samples` 计数。

如果使用 `-package`，加载器每 500ms 扫描一次匹配的 /proc 线程并维护 eBPF 的目标线程 map，在内核过滤事件。极短命启动线程可能出现在两次扫描之间，从而漏掉早期事件。遇到这种情况可以先不指定包名进行全局采集，再离线按 PID/TID 过滤。

BPF 层只读内核事件和调用栈；**不会注入 App、不使用 ptrace、不修改目标 SO**。但 Root、追踪配置、系统开销仍可能被高权限软件发现，因此不保证完全不可检测。

## 使用（Root shell）

默认安装：

```sh
cd /data/local/tmp/exit-tracer
chmod 755 exit-tracer exit-tracer-ebpf

# eBPF 优先，持续监控某 App
./exit-tracer start -package com.example.app

# 或全局捕获 60 秒，避免包名扫描漏掉极早期事件
./exit-tracer start -duration 60s

./exit-tracer status
./exit-tracer stop
```

每次运行新建 `/data/local/tmp/exit-tracer/runs/<time>-<pid>/`，最近目录写在 `latest.txt`。

查看后端：
```sh
D=$(cat /data/local/tmp/exit-tracer/latest.txt)
cat "$D/metadata.json" | grep backend
```

## 与 Frida Spawn 同时使用

先启动采集器，再启动 Frida：

```sh
# 手机上的 root shell：先全局采集，避免 500ms 包名扫描漏掉启动早期事件
./exit-tracer start
```

```sh
# 电脑上启动 Frida（按你的 Frida 版本需要选择恢复进程的方式）
frida -U -f com.example.app
```

这里的 Exit Tracer 独立于 Frida 工作。Frida 暂停目标进程期间，没有执行的代码不会产生退出事件；恢复运行后继续采集。如果使用 `-package`，eBPF 线程 map 每 500ms 扫描一次，可能错过极短命的进程；需要观察进程启动最早期时应使用全局采集。采集器仅记录内核事件与系统日志，不捕获 Frida 本身的 JavaScript Hook 事件。

## 原始输出目录

- `ebpf.0000.log`、`ebpf.0001.log` 等：eBPF JSONL 原始事件（成功运行 eBPF 时产生）
- `trace.0000.log` 等：tracefs 原始文本事件（仅回退时产生）
- `logcat.0000.log` 等：Android 系统、主、崩溃、事件日志
- `processes.jsonl`：目标进程/线程发现记录（仅指定包名时）
- `proc/<pid>/maps.txt`、`status.txt`、`cmdline.txt`：发现进程后的快照
- `activity_exit_info.txt`：Android 退出历史（指定包名时）
- `tombstones/`：本次采集时间内新增的 tombstones（不只限于目标包名）
- `metadata.json`：内核信息、包名、选用后端、时间等元信息
- `collector.log` / `ebpf.stderr.log`：运行错误和辅助进程状态

日志轮换：eBPF/tracefs 每段 16 MiB，保留最近 16 段；logcat 每段 16 MiB，保留最近 8 段。长时间采集会覆盖早期分段。采集结束后如没有出现指定事件，相应日志文件可能不存在。

## 原始 eBPF 事件示意（仅用于说明字段）

```json
{
  "type": "sys_enter",
  "syscall_nr": 94,
  "args": ["0x7","0x0","0x0"],
  "code": 7,
  "comm": "sh",
  "tgid": 1234,
  "tid": 1234,
  "mono_ns": 123456789,
  "observed_at": "2026-11-13T09:25:35Z",
  "user_stack_id": 52,
  "user_stack_pc": ["0x7000123456"]
}
```

`mono_ns` 是内核单调时间，`observed_at` 是采集器看到事件的墙上时间；不要直接混用。用户 PC 需要结合对应 PID 的 maps、ELF 加载基址再解析 SO 相对地址。

## 编译

在 zmwl 的源码目录 `D:\android-project\exit-tracer`：

```powershell
# 1. 编译 eBPF ELF（WSL Ubuntu 24.04, clang 18 + libbpf headers）
wsl -d Ubuntu-24.04 -e sh -lc 'cd /mnt/d/android-project/exit-tracer/ebpf && clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I/usr/include/x86_64-linux-gnu -c exit.bpf.c -o exit_bpfel.o'

# 2. 编译 eBPF 辅助程序（独立 Linux arm64 静态二进制）
cd D:\android-project\exit-tracer\ebpf
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags='-s -w' -o ..\exit-tracer-ebpf .

# 3. 编译 Android 主控
cd D:\android-project\exit-tracer
$env:GOOS='android'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags='-s -w' -o exit-tracer main.go
```

## 实机验证

环境：Pixel 6，Android 15，arm64，Kernel 5.10.209，Root 可用、SELinux Enforcing。

- eBPF 成功加载 3 个核心 tracepoint 和 `raw_syscalls/sys_enter`。
- 捕获到测试进程 `SIGTERM` 的信号产生、投递和用户态 PC。
- 捕获到 `exit_group(7)` 的 syscall nr 94、退出码 7 和用户态 PC。
- 成功写入 JSONL 并保存 logcat、metadata。
- 在没有 eBPF 辅助程序的独立 base 目录成功回退到 tracefs。
- 在指定包名模式中成功发现目标 PID/线程，并保存 maps。
- 定时停止后未留下 Exit Tracer 创建的 tracefs instance。

**已知限制：** 内核和安全策略不同可能导致 eBPF 不能加载；正常线程退出时可能没有可用的用户态栈；`-package` 使用进程扫描存在启动竞态；退出事件无法自动证明是反调试/检测行为；PC 与 SO 的对应关系需要后续离线分析。
