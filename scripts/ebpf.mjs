// SPDX-License-Identifier: GPL-3.0-or-later
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const rs = `${root}/src-rs`;

try {
  execFileSync('bpf-linker', ['--version'], { stdio: 'ignore' });
} catch {
  console.error('缺少 bpf-linker（Arch: sudo pacman -S bpf-linker）');
  process.exit(1);
}

// CARGO_ENCODED_RUSTFLAGS separates individual flags with \x1f (unit sep)
const rustflags = '--cfg=bpf_target_arch="aarch64"\u{1f}-Clink-arg=--btf';
const buildArgs = [
  'build', '-p', 'monitor-bpf', '--release',
  '--target', 'bpfel-unknown-none',
  '-Z', 'build-std=core,compiler_builtins',
  '-Z', 'build-std-features=compiler-builtins-mem',
];

let hasNightly = false;
try {
  execFileSync('rustup', ['run', 'nightly', 'cargo', '--version'], { stdio: 'ignore' });
  hasNightly = true;
} catch { /* fall through */ }

if (hasNightly) {
  execFileSync('rustup', ['run', 'nightly', 'cargo', ...buildArgs], {
    cwd: rs, stdio: 'inherit', env: { ...process.env, CARGO_ENCODED_RUSTFLAGS: rustflags },
  });
} else {
  execFileSync('cargo', buildArgs, {
    cwd: rs, stdio: 'inherit',
    env: { ...process.env, RUSTC_BOOTSTRAP: '1', CARGO_ENCODED_RUSTFLAGS: rustflags },
  });
}

const obj = `${rs}/target/bpfel-unknown-none/release/monitor-bpf`;
if (!existsSync(obj)) {
  console.error(`BPF 产物缺失: ${obj}`);
  process.exit(1);
}
console.log(`==> eBPF 产物: ${obj}`);
