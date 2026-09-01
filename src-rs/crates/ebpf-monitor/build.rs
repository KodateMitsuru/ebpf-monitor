// SPDX-License-Identifier: GPL-3.0-or-later
use std::path::PathBuf;

fn main() {
    let obj = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/bpfel-unknown-none/release/monitor-bpf");
    println!("cargo:rerun-if-changed={}", obj.display());

    if !obj.exists() {
        panic!(
            "BPF 产物不存在: {}\n\
             请先执行: pnpm ebpf（或 pnpm dist 一键全量）",
            obj.display()
        );
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::copy(&obj, out.join("monitor_bpf.o")).expect("copy bpf object");
}
