// SPDX-License-Identifier: GPL-3.0-or-later
// Cross-compiles the userspace daemon for ${ARCH}-unknown-linux-musl (default aarch64).
// Follows src-rs/README.md: cargo build --package ebpf-monitor --release --target=${ARCH}-unknown-linux-musl
// --config=target.${ARCH}-unknown-linux-musl.linker="rust-lld" (macOS) / clang on Linux via .cargo/config.toml
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
execFileSync('cargo', [
  'build', '--package', 'ebpf-monitor', '--release',
  '--target=aarch64-unknown-linux-musl',
  '--config=target.aarch64-unknown-linux-musl.linker="rust-lld"',
], { cwd: `${root}/src-rs`, stdio: 'inherit' });
console.log(`==> 用户态: ${root}/src-rs/target/aarch64-unknown-linux-musl/release/ebpf-monitor`);
