# ebpf-monitor

[English](README.md) | **简体中文**

eBPF 文件访问监视器。内核 raw tracepoint 记录对配置的文件名（basename）的每
一次创建、打开、改名、删除，并附执行该操作的进程信息：pid、uid、线程名、包
名、命令行、返回值。用户态守护进程保存事件，并通过本机控制套接字应用配置；
模块自带 KernelSU WebUI 管理目标与设置。

## 行为

- 监视的系统调用：`openat`（含 `O_CREAT`）、`openat2`、`creat`、`mkdir`、
  `mkdirat`、`rename`、`renameat`、`renameat2`、`unlink`、`unlinkat`
- 按 basename 匹配文件；uid 经 `/data/system/packages.list` 解析为包名；应用
  uid 段以外的进程从 `/proc/<pid>/cmdline` 捕获命令行
- 配置文件位于 `/data/adb/ebpf-monitor/config.toml`，定义监视目标、操作组、
  uid/pid 白名单与全量打印开关。每次写入都先校验、原子落盘，再应用到 BPF
  表，无需重启
- 事件追加写入 JSONL 日志（2 MB 轮转），与 WebUI 共用同一本机 UNIX socket
  查询

## 安装

1. 在 KernelSU Manager 刷入 `dist/ebpf-monitor.zip`，重启。安装器会在设备上
   执行 eBPF 装载自测，无法承载本模块的内核会在安装阶段直接拒绝
2. 打开模块的 WebUI，添加要监视的文件名，勾选要记录的操作组

诊断：`ebpf-monitor ctl status`、`adb logcat -s ebpf-monitor`。

## 构建

```bash
# 前置：Rust stable + nightly、bpf-linker、pnpm
pnpm install
pnpm dist          # 内核 + aarch64-musl 守护进程 + 前端 → dist/ebpf-monitor.zip
pnpm dev           # 前端开发服务器（mock 传输层）

cd src-rs
cargo test -p ebpf-monitor            # ABI 布局 + 发布配置校验
./target/debug/ebpf-monitor --selftest
```

## 结构

```
/               前端（Vue 3 + Vite + TypeScript）
├── src/        WebUI 源码
├── scripts/    构建编排（node ESM）
├── template/   KernelSU 模块模板（打包时注入版本号）
├── src-rs/     Rust workspace：ebpf-monitor（守护进程）、monitor-bpf（内核侧）
└── docs/       实现文档
```

## 文档

[实现细节（英文）](docs/implement.md) · [中文](docs/implement_CN.md)

## 许可

GPL-3.0-or-later，见 [LICENSE](LICENSE)。
