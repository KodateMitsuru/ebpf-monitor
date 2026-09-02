# ebpf-monitor — implementation notes

## Layout

```
src/            WebUI (Vue 3 + Vite, miuix-vue, @automerge/automerge)
src-rs/
  ebpf-monitor          daemon (config / Automerge forest / ipc / bpf_loader / btf)
  ebpf-monitor-ctl      control client (single sync)
  ebpf-monitor-common   shared ABI (FileEvent, SyscallArgInfo, FileOp)
  ebpf-monitor-ebpf     kernel program (no_std, aya-ebpf)
template/       KernelSU module template (version injected at build)
dist/           webroot + ebpf-monitor.zip
```

## Data path

```
kernel (raw_tracepoint sys_enter / sys_exit)
  -> ringbuf -> daemon
       -> Automerge forest.bin  (Map<file_id, List<Event>> hash=blake3, prev_hash chain)
       -> ctl.sock (JSON over UNIX socket, 0700)
            ^- WebUI via `ksud exec ebpf-monitor-ctl sync` (base64 Automerge doc merge) and `ksud module config get/set --temp` for pid
```

## Configuration

Per-key KernelSU storage, not a single file:

- `watch.basenames` — JSON array of basenames
- `watch.groups` — JSON array of groups (`create` / `create_any` / `rename_` / `delete`)
- `whitelist.uid` / `whitelist.pid` — JSON arrays
- `print.groups` — JSON array (empty = off)

`Config::load()` reads each key via `ksud`, falling back to `factory_default()`; `Config::save()` writes them individually and triggers `ctl reload`, which validates and reloads BPF maps (syscall args, watch set, whitelists) without restart.

## Kernel program

- `raw_tracepoint` on `sys_enter`/`sys_exit`; object embedded in the daemon and loaded from memory
- `task_struct.thread_info.flags` offset and `_TIF_32BIT` mask are resolved from `vmlinux` BTF at load time and injected via `CONFIG` array (no CO-RE relocations)
- Maps: `ARGS64`/`ARGS32` (syscall arg slots), `WATCH_RULES`, `UID_WL`/`PID_WL`, `PENDING` (per-thread), `EVENTS` (ringbuf)

Verifier constraints kept: never reset loop counters, mask indices before pointer arithmetic, basename match scans backwards from path end within a bounded window.

## Module lifecycle

- `customize.sh` checks KernelSU / arm64 / BTF, then runs `ebpf-monitor --loadtest` (real map + program load, immediately unloaded); failure aborts install
- `service.sh` creates `/data/adb/ebpf-monitor` and starts the daemon
- `action.sh` prints version / `ctl status` / recent events
