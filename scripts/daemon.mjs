// SPDX-License-Identifier: GPL-3.0-or-later
// Cross-compiles the userspace daemon for aarch64-linux-android via NDK.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
execFileSync('cargo', [
  'ndk', '-t', 'arm64-v8a',
  'build', '--release', '-p', 'ebpf-monitor',
], { cwd: `${root}/src-rs`, stdio: 'inherit' });
console.log(`==> 用户态: ${root}/src-rs/target/aarch64-linux-android/release/ebpf-monitor`);
