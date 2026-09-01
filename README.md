# ebpf-monitor

**English** | [简体中文](README_CN.md)

An eBPF file-access monitor. Kernel raw tracepoints record every create,
open, rename and delete of the configured file names (basenames), together
with the process that performed the operation: pid, uid, thread name,
package, command line and return value. A userspace daemon stores the events
and applies configuration changes through a local control socket; a
KernelSU module WebUI manages targets and settings.

## Behavior

- Watched syscalls: `openat` (with `O_CREAT`), `openat2`, `creat`, `mkdir`,
  `mkdirat`, `rename`, `renameat`, `renameat2`, `unlink`, `unlinkat`
- Files are matched by basename. The uid is resolved to a package name from
  `/data/system/packages.list`; for processes outside the app range the
  command line is captured from `/proc/<pid>/cmdline`
- The configuration file at `/data/adb/ebpf-monitor/config.toml` defines the
  watch targets, operation groups, uid/pid whitelists and a print-all mode.
  Every write is validated, persisted atomically, and applied to the BPF
  maps without a restart
- Events are appended to a JSONL log (rotated at 2 MB) and queried over the
  same local UNIX socket the WebUI uses

## Install

1. Flash `dist/ebpf-monitor.zip` in KernelSU Manager, then reboot. The
   installer runs an on-device eBPF load self-test and refuses to install on
   kernels that cannot host the module
2. Open the module's WebUI, add the file names to watch, and select the
   operation groups to record

Diagnostics: `ebpf-monitor ctl status`, `adb logcat -s ebpf-monitor`.

## Build

```bash
# prerequisites: Rust stable + nightly, bpf-linker, pnpm
pnpm install
pnpm dist          # kernel + aarch64-musl daemon + frontend → dist/ebpf-monitor.zip
pnpm dev           # frontend dev server (with mock transport)

cd src-rs
cargo test -p ebpf-monitor            # ABI layout + shipped-config checks
./target/debug/ebpf-monitor --selftest
```

## Layout

```
/               frontend (Vue 3 + Vite + TypeScript)
├── src/        WebUI sources
├── scripts/    build orchestration (node ESM)
├── template/   KernelSU module template (version is injected at packaging)
├── src-rs/     Rust workspace: ebpf-monitor (daemon), monitor-bpf (kernel)
└── docs/       implementation notes
```

## Documentation

[Implementation notes](docs/implement.md) · [简体中文](docs/implement_CN.md)

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
