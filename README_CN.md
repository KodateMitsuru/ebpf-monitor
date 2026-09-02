# ebpf-monitor

[English](README.md) | **简体中文**

基于 raw tracepoint 的文件访问监视。跟踪 `openat`/`openat2`/`creat`/`mkdir`/`mkdirat`/`rename*`/`unlink*` 的 basename 命中，记录 pid/uid/comm/pkg/cmd/ret。守护进程以 SQLite 持久化事件并提供控制套接字；KernelSU WebUI 按键分键编辑配置。

## 行为

- 按 basename 匹配；uid 通过 `/data/system/packages.list` 解析为包名
- 配置位于 KernelSU 模块存储（`ksud module config`）：`watch.basenames`, `watch.groups`, `whitelist.uid`, `whitelist.pid`, `print.groups`；校验后重载 BPF 表，无需重启
- 事件位于 `/data/adb/ebpf-monitor/events.db`（SQLite，限容），经 `ctl.sock` 查询

## 安装

1. 在 KernelSU Manager 刷入 `dist/ebpf-monitor.zip` 并重启（`customize.sh` 执行 `--loadtest`，不兼容内核直接拒绝安装）
2. 在 WebUI “监视规则”中添加 basename 并勾选操作组

诊断：`ebpf-monitor ctl status`、`adb logcat -s ebpf-monitor`。

## 构建

```bash
pnpm install
pnpm run build
pnpm dev
```

## 结构

```
src/            WebUI
src-rs/         ebpf-monitor / ebpf-monitor-common / ebpf-monitor-ebpf
template/       模块模板
docs/           实现说明
```

## 许可

GPL-3.0-or-later
