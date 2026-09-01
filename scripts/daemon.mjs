// SPDX-License-Identifier: GPL-3.0-or-later
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
execFileSync('cargo', [
  'build', '--target', 'aarch64-unknown-linux-musl', '--release', '-p', 'ebpf-monitor',
], { cwd: `${root}/src-rs`, stdio: 'inherit' });
console.log(`==> 用户态: ${root}/src-rs/target/aarch64-unknown-linux-musl/release/ebpf-monitor`);
