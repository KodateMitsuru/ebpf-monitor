# ebpf-monitor

**English** | [简体中文](README_CN.md)

File-access monitor via raw tracepoints. Tracks basename matches for `openat`/`openat2`/`creat`/`mkdir`/`mkdirat`/`rename*`/`unlink*`, recording pid/uid/comm/pkg/cmd/ret. The daemon persists events in SQLite and exposes a control socket; the KernelSU WebUI edits per-key settings.

## Behavior

- Match by basename; uid → package via `/data/system/packages.list`
- Configuration lives in KernelSU module storage (`ksud module config get/set`): `watch.basenames`, `watch.groups`, `whitelist.uid`, `whitelist.pid`, `print.groups`; changes validate and reload BPF maps without restart
- Events stored in `/data/adb/ebpf-monitor/events.db` (SQLite, capped); queried via `ctl.sock`

## Install

1. Flash `dist/ebpf-monitor.zip` in KernelSU Manager and reboot (`customize.sh` runs `--loadtest` and aborts on incompatible kernels)
2. In the WebUI add basenames and select watch groups under “监视规则”

Diagnostics: `ebpf-monitor ctl status`, `adb logcat -s ebpf-monitor`.

## Build

```bash
pnpm install
pnpm run build   # daemon (aarch64) + frontend -> dist/ebpf-monitor.zip
pnpm dev         # frontend dev server (mock)
```

## Layout

```
src/            WebUI (Vue 3 + Vite)
src-rs/         Rust workspace: ebpf-monitor (daemon) / ebpf-monitor-common (ABI) / ebpf-monitor-ebpf (kernel)
template/       KernelSU module template (version injected at build)
docs/           implementation notes
```

## License

GPL-3.0-or-later
