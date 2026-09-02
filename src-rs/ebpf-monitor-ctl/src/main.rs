// SPDX-License-Identifier: GPL-3.0-or-later
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "\
ebpf-monitor-ctl - control client for ebpf-monitor daemon

USAGE:
    ebpf-monitor-ctl <method> [args]

METHODS:
    ping
    status
    events [after <n>] [limit <n>]
    clear
    get-config
    set-config <FILE|->   (JSON, validate -> persist -> reload)
    reload
    sync                (Automerge forest doc, base64)
";

fn resolve_sock() -> PathBuf {
    if let Ok(dir) = std::env::var("EBPF_MONITOR_DIR") {
        return PathBuf::from(dir).join("ctl.sock");
    }
    PathBuf::from("/data/adb/ebpf-monitor/ctl.sock")
}

fn parse_args(args: &[String]) -> (String, u64, u64, Option<String>) {
    let method = args.first().cloned().unwrap_or_default();
    let mut after = 0u64;
    let mut limit = 500u64;
    let mut body: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "after" if i+1 < args.len() => { after = args[i+1].parse().unwrap_or(0); i+=2; }
            "limit" if i+1 < args.len() => { limit = args[i+1].parse().unwrap_or(500); i+=2; }
            other => { body = Some(other.to_string()); i+=1; }
        }
    }
    (method, after, limit, body)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0]=="-h" || args[0]=="--help" {
        print!("{USAGE}");
        return std::process::ExitCode::from(0);
    }
    let (method, after, limit, body) = parse_args(&args);
    let sock = resolve_sock();
    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(_) => {
            println!("{}", serde_json::json!({"ok":false,"error":"daemon not running","daemon":false}));
            return std::process::ExitCode::from(1);
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let req = match method.as_str() {
        "ping" => serde_json::json!({"cmd":"ping"}),
        "status" => serde_json::json!({"cmd":"status"}),
        "events" => serde_json::json!({"cmd":"events","after":after,"limit":limit}),
        "clear" => serde_json::json!({"cmd":"clear"}),
        "get-config" | "config-get" => serde_json::json!({"cmd":"get-config"}),
        "reload" => serde_json::json!({"cmd":"reload"}),
        "sync" => serde_json::json!({"cmd":"sync"}),
        "set-config" | "config-set" => serde_json::json!({"cmd":"set-config"}),
        other => serde_json::json!({"cmd":other}),
    };
    let _ = stream.write_all(serde_json::to_string(&req).unwrap().as_bytes());
    let _ = stream.write_all(b"\n");
    if method=="set-config" || method=="config-set" {
        let body_bytes: Vec<u8> = if let Some(f)=body.clone() {
            if f=="-" { let mut v=Vec::new(); let _= std::io::stdin().read_to_end(&mut v); v } else { std::fs::read(&f).unwrap_or_default() }
        } else { Vec::new() };
        let _ = stream.write_all(&body_bytes);
    } else if method=="sync" {
        if let Some(f)=body {
            let b = if f=="-" { let mut v=Vec::new(); let _= std::io::stdin().read_to_end(&mut v); v } else { std::fs::read(&f).unwrap_or_default() };
            let _ = stream.write_all(&b);
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    if method=="sync" {
        let mut resp=String::new();
        let _ = stream.read_to_string(&mut resp);
        print!("{}", resp);
        return if resp.contains("\"doc\"") { std::process::ExitCode::from(0) } else { std::process::ExitCode::from(1) };
    }
    let mut resp=String::new();
    let _ = stream.read_to_string(&mut resp);
    print!("{}", resp);
    if resp.contains("\"ok\":true") { std::process::ExitCode::from(0) } else { std::process::ExitCode::from(1) }
}
