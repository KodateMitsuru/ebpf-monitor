// SPDX-License-Identifier: GPL-3.0-or-later
// Official aya pipeline: compile the kernel-side crate with aya-build
// (nightly -Z build-std, bpf-linker, and the rustflags it owns, notably
// -Cdebuginfo=2 which the loader's function relocation depends on).
use aya_build::{build_ebpf, Package, Toolchain};

fn main() -> aya_build::Result<()> {
    build_ebpf(
        [Package {
            name: "monitor-bpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../monitor-bpf"),
            ..Default::default()
        }],
        Toolchain::default(),
    )
}
