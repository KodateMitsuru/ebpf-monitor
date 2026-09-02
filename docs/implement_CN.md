# ebpf-monitor — 实现细节

## 结构

```
src/            WebUI
src-rs/
  ebpf-monitor          守护进程 (Automerge 森林)
  ebpf-monitor-ctl      控制端 (单 sync)
  ebpf-monitor-common   共享 ABI
  ebpf-monitor-ebpf     内核程序
template/       模块模板
dist/           webroot + zip
```

## 数据通路

```
内核 raw_tracepoint sys_enter / sys_exit
  -> ringbuf -> 守护进程
       -> Automerge forest.bin (Map<file_id, List<Event>> hash=blake3, prev_hash 链)
       -> ctl.sock（0700 目录下 JSON over UNIX socket）
            ^- WebUI 经 ebpf-monitor-ctl sync (base64 doc 合并) 与 ksud module config（pid 用 --temp）
```

## 配置

按键分键存储于 KernelSU：

- `watch.basenames`、`watch.groups`（`create`/`create_any`/`rename_`/`delete`）
- `whitelist.uid` / `whitelist.pid`
- `print.groups`（空即关闭）

`Config::load()` 逐键读取并回退到 `factory_default()`；`Config::save()` 逐键写入后触发 `ctl reload` 校验并重载 BPF 表，无需重启。

## 内核程序

- `raw_tracepoint`，对象内嵌于守护进程
- `thread_info.flags` 偏移与 `_TIF_32BIT` 掩码由 BTF 在装载时解析并注入 `CONFIG` 数组
- 表：`ARGS64`/`ARGS32`、`WATCH_RULES`、`UID_WL`/`PID_WL`、`PENDING`、`EVENTS`

需维持的 verifier 约束：循环内不重置计数器、索引先掩码再作指针运算、basename 自路径末端反向有界扫描。

## 模块生命周期

- `customize.sh` 校验环境后执行 `--loadtest` 真实装载，失败则中止安装
- `service.sh` 创建持久化目录并启动守护进程
- `action.sh` 输出版本 / 状态 / 近期事件
