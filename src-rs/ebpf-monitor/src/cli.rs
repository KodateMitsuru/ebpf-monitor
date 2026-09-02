// SPDX-License-Identifier: GPL-3.0-or-later

const USAGE: &str = "\
ebpf-monitor - eBPF file monitor (daemon)

USAGE:
    ebpf-monitor [OPTIONS]

OPTIONS:
    -q                quiet
    -v                verbose events
    -vv               debug
    --selftest        offline self-test (BPF object + IPC, no root)
    --loadtest        on-device load test (requires root)
    -h, --help        help
";

pub struct CliArgs {
    pub verbosity: u8,
    pub selftest: bool,
    pub loadtest: bool,
}

pub fn parse() -> CliArgs {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut verbosity: u8 = 1;
    let mut selftest = false;
    let mut loadtest = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--selftest" => { selftest = true; i += 1; }
            "--loadtest" => { loadtest = true; i += 1; }
            "-q" => { verbosity = 0; i += 1; }
            "-vv" => { verbosity = 3; i += 1; }
            "-v" => { verbosity = 2; i += 1; }
            "-h" | "--help" => { println!("{USAGE}"); std::process::exit(0); }
            other => {
                eprintln!("error: unknown option '{other}' (use ebpf-monitor-ctl for control)");
                eprintln!("{USAGE}");
                std::process::exit(1);
            }
        }
    }
    CliArgs { verbosity, selftest, loadtest }
}
