# ebpf-monitor — implementation notes

[English](implement.md) | [简体中文](implement_CN.md)

## Layout

```
/               frontend project; package.json supplies the version injected into module.prop
├── scripts/    build orchestration (node ESM)
├── template/   module files; module.prop contains the ${VERSION}/${VERSION_CODE} placeholders
├── dist/       build output: webroot/ (frontend) + ebpf-monitor.zip
└── src-rs/
    ├── .cargo/config.toml    aarch64-unknown-linux-musl is linked with rust-lld
    └── crates/
        ├── ebpf-monitor/     the daemon (config / types / ipc / cli); build.rs compiles the kernel crate via aya-build
        └── monitor-bpf/      the kernel program (no_std, aya-ebpf) and its copy of the ABI types
```

## Data path

```
kernel program (raw tracepoints: sys_enter / sys_exit)
  └─ ringbuf → daemon (ebpf-monitor)
        ├─ events.jsonl   /data/adb/ebpf-monitor (appended, rotated at 2 MB)
        ├─ logcat         tag ebpf-monitor, through a dlopen'd liblog.so
        └─ ctl.sock       JSONL request/response over a UNIX socket in a 0700 directory
              ↑
WebUI (miuix-vue) → kernelsu exec → `ebpf-monitor ctl …`
```

## Configuration

- On disk: `/data/adb/ebpf-monitor/config.toml`. It is seeded from
  `template/config.toml` on first boot; module upgrades never overwrite it.
- On the wire: the entire configuration travels as one JSON document (a
  serde round trip of the `Config` type). `ctl get-config` returns it, and
  `ctl set-config <FILE|->` accepts it.
- On apply: deserialize → validate → serialize back to TOML → atomic rename
  into place → rebuild the BPF maps (syscall argument table, watch basenames,
  whitelists). An invalid document is rejected before anything is written.
- `ctl config-get` / `ctl config-set` expose the same pipeline in raw TOML
  for manual editing.
- The WebUI keeps a local mirror and stays truthful: every control change
  submits the whole document, and a rejection by the daemon restores the
  previous snapshot.

## Module lifecycle

- `customize.sh` requires KernelSU, arm64 and kernel BTF, sets permissions,
  then runs `ebpf-monitor --loadtest` — real map creation, program load and
  tracepoint attach, immediately unloaded. Any failure aborts the install,
  so an incompatible kernel never gets a silently dead module
- `service.sh` waits for boot, creates `/data/adb/ebpf-monitor` (0700),
  seeds config.toml on first run and starts the daemon
- `action.sh` (KSU terminal): version, `ctl status`, last 20 events
- `uninstall.sh` stops the daemon and removes `/data/adb/ebpf-monitor`

## Event fields

`seq, ts, epoch_ms, pid, tid, uid, comm, pkg, op, ret, flags, file, cmd`
— `pkg` is resolved from `/data/system/packages.list`; `cmd` holds the
command line read from `/proc/<pid>/cmdline` for callers outside the app uid
range.

## Kernel program

- Written in Rust against `aya-ebpf`; the object is embedded in the daemon
  binary and loaded from memory.
- `task_struct.thread_info.flags` is read at offset 0 (on arm64,
  `thread_info` is the first member of `task_struct` and `flags` its first
  field). No CO-RE relocations are used.
- Maps: the syscall argument tables (64-bit and 32-bit), the uid/pid
  whitelists, the pending per-thread context, the watch-basename set, and
  the event ring buffer.
- Verifier constraints the code must maintain:
  - a loop must never reset its counter (resetting triggers state explosion
    and `E2BIG`)
  - an index is masked into an unsigned bound before it is used for pointer
    arithmetic
  - basename matching scans backward from the end of the path under a
    compile-time bound
- The ABI types (PrintEvent / PendingPrint / SyscallArgInfo and the shared
  constants) exist as separate copies in the two crates because a std crate
  and a no_std crate cannot be shared; `size_of` assertions (304 / 24 / 16)
  in both crates detect drift.

## Build

```bash
rustup toolchain install nightly --profile minimal   # once; the kernel build needs -Z build-std
# install bpf-linker with your distribution's package manager

pnpm install
pnpm dev          # frontend dev server
pnpm daemon       # aarch64-musl daemon; build.rs compiles the kernel object first
pnpm dist         # daemon (kernel + userspace) -> frontend -> module zip

cd src-rs
cargo test -p ebpf-monitor
./target/debug/ebpf-monitor --selftest   # checks the embedded object and a ctl round trip; no root
```

Details:

- `crates/ebpf-monitor/build.rs` calls `aya_build::build_ebpf`, which drives a
  nightly `cargo build --package monitor-bpf --target bpfel-unknown-none
  -Z build-std=core` and sets `CARGO_ENCODED_RUSTFLAGS` to
  `--cfg=bpf_target_arch="<arch>"` + `-Cdebuginfo=2` + `-Clink-arg=--btf`.
  The resulting object is copied into `OUT_DIR` and embedded by `main.rs`
  with `include_bytes!`. aya-build owns these flags; do not hand-copy them —
  omitting `-Cdebuginfo=2` drops the func_info aya needs to relocate calls
  into compiler-builtins helpers, failing load with
  `function 0x… not found while relocating`.
- The zip is written by yazl: files are deflate-compressed, directory
  entries stored; unix modes are 0755 for `*.sh` and the binary, 0644 for
  everything else.
