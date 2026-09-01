// SPDX-License-Identifier: GPL-3.0-or-later
use std::path::PathBuf;

const USAGE: &str = "\
ebpf-monitor - eBPF 文件访问监视器

USAGE:
    ebpf-monitor [OPTIONS]              运行守护进程（前台）
    ebpf-monitor ctl <method> [args]    通过 UNIX socket 查询/控制运行中的守护进程

CTL METHODS:
    ping                            存活探测
    status                          状态（事件序号水位）
    events [after <n>] [limit <n>]  结构化事件（JSON，seq 升序）
    clear                           清空事件（内存环 + 文件；seq 不回退）
    config-get                      输出当前 config.toml 原文
    config-set <FILE|->             用给定 TOML 替换配置（校验通过后原子写入并立即热重载）
    get-config                      输出结构化配置（JSON，供控件界面读写）
    set-config <FILE|->             用给定 JSON 配置替换（校验→序列化 TOML→热重载）
    reload                          从磁盘配置热重载

OPTIONS:
    -c <path>         配置文件路径（默认 ./config.toml）
    -q                静默模式，仅输出错误
    -v                显示监视事件
    -vv               调试输出
    --selftest        离线自检（内嵌 BPF 对象完整性 + IPC 往返，无需 root）
    --loadtest        真机加载自测（装载并挂载 BPF 程序后立即卸载，需要 root）
    -h, --help        显示帮助";

pub struct CliArgs {
    pub config_path: Option<PathBuf>,
    pub verbosity: u8,
    pub selftest: bool,
    pub loadtest: bool,
}

pub struct CtlCall {
    pub method: String,
    pub after: u64,
    pub limit: u64,
    pub body_file: Option<String>,
}

pub enum Action {
    Serve(CliArgs),
    Ctl(CtlCall),
}

pub fn parse() -> Action {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "ctl" {
        return Action::Ctl(parse_ctl(&args[2..]));
    }
    Action::Serve(parse_serve(&args[1..]))
}

fn parse_ctl(args: &[String]) -> CtlCall {
    let mut call = CtlCall {
        method: String::new(),
        after: 0,
        limit: 500,
        body_file: None,
    };
    let mut i = 0;
    if let Some(m) = args.first() {
        call.method = m.clone();
        i = 1;
    }
    while i < args.len() {
        match args[i].as_str() {
            "after" if i + 1 < args.len() => {
                call.after = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "limit" if i + 1 < args.len() => {
                call.limit = args[i + 1].parse().unwrap_or(500);
                i += 2;
            }
            other => {
                call.body_file = Some(other.to_string());
                i += 1;
            }
        }
    }
    call
}

fn parse_serve(args: &[String]) -> CliArgs {
    let mut config_path = None;
    let mut verbosity: u8 = 1;
    let mut selftest = false;
    let mut loadtest = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--selftest" => {
                selftest = true;
                i += 1;
            }
            "--loadtest" => {
                loadtest = true;
                i += 1;
            }
            "-q" => {
                verbosity = 0;
                i += 1;
            }
            "-vv" => {
                verbosity = 3;
                i += 1;
            }
            "-v" => {
                verbosity = 2;
                i += 1;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-c" if i + 1 < args.len() => {
                config_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-c" => {
                eprintln!("error: -c requires a value");
                std::process::exit(1);
            }
            other => {
                eprintln!("error: unknown option '{other}'");
                eprintln!("{USAGE}");
                std::process::exit(1);
            }
        }
    }

    if config_path.is_none() {
        let default_path = PathBuf::from("config.toml");
        if default_path.exists() {
            config_path = Some(default_path);
        }
    }

    CliArgs {
        config_path,
        verbosity,
        selftest,
        loadtest,
    }
}
