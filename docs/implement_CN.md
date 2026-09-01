# ebpf-monitor — 实现细节

[English](implement.md) | **简体中文**

## 结构

```
/               前端工程；package.json 提供注入 module.prop 的版本号
├── scripts/    构建编排（node ESM）
├── template/   模块文件；module.prop 含 ${VERSION}/${VERSION_CODE} 占位符
├── dist/       构建产物：webroot/（前端）+ ebpf-monitor.zip
└── src-rs/
    ├── .cargo/config.toml    aarch64-unknown-linux-musl 用 rust-lld 链接
    └── crates/
        ├── ebpf-monitor/     守护进程（config / types / ipc / cli）；build.rs 经 aya-build 编译内核 crate
        └── monitor-bpf/      内核程序（no_std，aya-ebpf）及其一份 ABI 类型副本
```

## 数据通路

```
内核程序（raw tracepoint：sys_enter / sys_exit）
  └─ ringbuf → 守护进程（ebpf-monitor）
        ├─ events.jsonl   /data/adb/ebpf-monitor（追加写，2 MB 轮转）
        ├─ logcat         tag ebpf-monitor，经 dlopen liblog.so
        └─ ctl.sock       0700 目录下 UNIX socket 上的 JSONL 请求/应答
              ↑
WebUI（miuix-vue）→ kernelsu exec → `ebpf-monitor ctl …`
```

## 配置

- 磁盘上：`/data/adb/ebpf-monitor/config.toml`。首次启动从
  `template/config.toml` 复制，模块升级不覆盖。
- 传输上：整份配置作为一个 JSON 文档往返（`Config` 的 serde）。
  `ctl get-config` 返回它，`ctl set-config <FILE|->` 接受它。
- 应用时：反序列化 → 校验 → 重新序列化 TOML → 原子 rename 落位 → 重建 BPF
  表（syscall 参数表、watch basename、白名单）。非法文档在任何写入前即被拒绝。
- `ctl config-get` / `ctl config-set` 以 TOML 原文形态提供同一通路，便于手工
  编辑。
- WebUI 维护一份本地镜像并保持与守护进程一致：每次控件改动提交整份文档，
  若被拒绝则回滚到上一快照。

## 模块生命周期

- `customize.sh` 校验 KernelSU、arm64 与内核 BTF，设置权限后执行
  `ebpf-monitor --loadtest`——真实建 map、装载程序、挂载 raw tracepoint，
  随即卸载。任一步失败即中止安装，不兼容的内核不会得到一个静默失效的模块
- `service.sh` 等待开机完成，创建 `/data/adb/ebpf-monitor`（0700），
  首次运行时播种 config.toml 并启动守护进程
- `action.sh`（KSU 终端入口）：版本、`ctl status`、最近 20 条事件
- `uninstall.sh` 停止守护进程并删除 `/data/adb/ebpf-monitor`

## 事件字段

`seq, ts, epoch_ms, pid, tid, uid, comm, pkg, op, ret, flags, file, cmd`
——`pkg` 由 `/data/system/packages.list` 解析；`cmd` 为应用 uid 段以外的调用方
从 `/proc/<pid>/cmdline` 读取的命令行。

## 内核程序

- 用 Rust 面向 `aya-ebpf` 编写；对象内嵌进守护进程二进制，从内存加载。
- 按偏移 0 读取 `task_struct.thread_info.flags`（arm64 上 `thread_info` 是
  `task_struct` 的首成员、`flags` 是其首字段）。不使用 CO-RE 重定位。
- maps：syscall 参数表（64 位与 32 位）、uid/pid 白名单、按线程暂存的 pending
  上下文、watch-basename 集合、事件 ringbuf。
- 代码必须维持的 verifier 约束：
  - 循环内绝不重置计数器（重置会触发状态爆炸与 `E2BIG`）
  - 下标在用于指针运算前先掩码成无符号边界
  - basename 匹配在编译期上界下自路径末端反向扫描
- ABI 类型（PrintEvent / PendingPrint / SyscallArgInfo 及共享常量）在两个
  crate 各存一份，因为 std crate 与 no_std crate 无法共用；两侧 `size_of`
  断言（304 / 24 / 16）监测漂移。

## 构建

```bash
rustup toolchain install nightly --profile minimal   # 仅首次；内核侧构建需 -Z build-std
# 用发行版的包管理器安装 bpf-linker

pnpm install
pnpm dev          # 前端开发服务器
pnpm daemon       # aarch64-musl 守护进程；build.rs 会先编译内核对象
pnpm dist         # 守护进程（内核 + 用户态）-> 前端 -> 模块 zip

cd src-rs
cargo test -p ebpf-monitor
./target/debug/ebpf-monitor --selftest   # 校验内嵌对象与一次 ctl 往返，无需 root
```

细节：

- `crates/ebpf-monitor/build.rs` 调用 `aya_build::build_ebpf`，它驱动
  nightly `cargo build --package monitor-bpf --target bpfel-unknown-none
  -Z build-std=core`，并把 `CARGO_ENCODED_RUSTFLAGS` 设为
  `--cfg=bpf_target_arch="<arch>"` + `-Cdebuginfo=2` + `-Clink-arg=--btf`。
  产物复制进 `OUT_DIR`，`main.rs` 以 `include_bytes!` 内嵌。这些 flag 归
  aya-build 所有，不要手抄——漏掉 `-Cdebuginfo=2` 会丢 func_info，aya 无法重定位
  对 compiler-builtins 辅助函数的调用，加载即报
  `function 0x… not found while relocating`。
- zip 由 yazl 写出：文件 deflate 压缩、目录项 stored；unix 权限对 `*.sh`
  与二进制设 0755，其余设 0644。
