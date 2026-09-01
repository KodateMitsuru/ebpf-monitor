// SPDX-License-Identifier: GPL-3.0-or-later
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

use serde_json::{json, Value};

use crate::events;

pub enum Req {
    Reload {
        toml: String,
        reply: SyncSender<Result<(), String>>,
    },
}

pub struct Ipc {
    pub socket: PathBuf,
    config_path: PathBuf,
    tx: SyncSender<Req>,
}

impl Ipc {
    pub fn new(persist_dir: PathBuf, config_path: PathBuf, tx: SyncSender<Req>) -> Self {
        Self {
            socket: persist_dir.join("ctl.sock"),
            config_path,
            tx,
        }
    }

    pub fn bind(&self) -> std::io::Result<UnixListener> {
        if self.socket.exists() {
            let _ = std::fs::remove_file(&self.socket);
        }
        let l = UnixListener::bind(&self.socket)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.socket, std::fs::Permissions::from_mode(0o600));
        }
        Ok(l)
    }

    pub fn serve(&self, listener: UnixListener) {
        let tx = self.tx.clone();
        let config_path = self.config_path.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if let Ok(stream) = conn {
                    let tx = tx.clone();
                    let cfg = config_path.clone();
                    std::thread::spawn(move || serve_conn(stream, tx, cfg));
                }
            }
        });
    }
}

fn write_line(stream: &mut UnixStream, v: Value) {
    let s = serde_json::to_string(&v).unwrap_or_else(|_| "{}".into());
    let _ = stream.write_all(s.as_bytes());
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

fn serve_conn(mut stream: UnixStream, tx: SyncSender<Req>, config_path: PathBuf) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

    let mut line = String::new();
    {
        let mut b = [0u8; 1];
        loop {
            match stream.read(&mut b) {
                Ok(0) => return,
                Ok(_) => {
                    line.push(b[0] as char);
                    if b[0] == b'\n' {
                        break;
                    }
                    if line.len() > 8192 {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }
    let Ok(req) = serde_json::from_str::<Value>(line.trim_end()) else {
        return;
    };
    let cmd = req
        .get("cmd")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    match cmd.as_str() {
        "ping" => write_line(&mut stream, json!({"ok":true,"pong":true})),
        "status" => {
            let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            write_line(
                &mut stream,
                json!({
                    "ok": true,
                    "newest": events::newest_seq(),
                    "kernel": kernel,
                    "btf": Path::new("/sys/kernel/btf/vmlinux").exists(),
                    "events_bytes": events::file_len(),
                    "daemon_pid": std::process::id()
                }),
            );
        }
        "events" => {
            let after = req.get("after").and_then(Value::as_u64).unwrap_or(0);
            let limit = req
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(500)
                .min(2000) as usize;
            let evs: Vec<Value> = events::query(after, limit)
                .iter()
                .filter_map(|e| serde_json::from_str(&e.to_json()).ok())
                .collect();
            write_line(&mut stream, json!({"ok":true,"events":evs}));
        }
        "clear" => {
            events::clear();
            write_line(&mut stream, json!({"ok":true,"cleared":true}));
        }
        "config-get" => match std::fs::read_to_string(&config_path) {
            Ok(c) => write_line(&mut stream, json!({"ok":true,"content":c})),
            Err(e) => write_line(
                &mut stream,
                json!({"ok":false,"error":format!("read config: {e}")}),
            ),
        },
        "get-config" => {
            let cfg = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("read: {e}"))
                .and_then(|t| {
                    crate::config::Config::from_toml_str(&t).map_err(|e| format!("parse: {e}"))
                });
            match cfg {
                Ok(c) => match serde_json::to_value(&c) {
                    Ok(v) => write_line(&mut stream, json!({"ok":true,"config":v})),
                    Err(e) => write_line(
                        &mut stream,
                        json!({"ok":false,"error":format!("tojson: {e}")}),
                    ),
                },
                Err(e) => write_line(&mut stream, json!({"ok":false,"error":e})),
            }
        }
        "set-config" => {
            let mut content = Vec::new();
            if stream.read_to_end(&mut content).is_err() || content.is_empty() {
                write_line(&mut stream, json!({"ok":false,"error":"empty body"}));
                return;
            }
            let toml_text = match serde_json::from_slice::<crate::config::Config>(&content) {
                Ok(c) => match c.validate() {
                    Ok(_) => match c.to_toml_str() {
                        Ok(t) => t,
                        Err(e) => {
                            write_line(
                                &mut stream,
                                json!({"ok":false,"error":format!("ser: {e}")}),
                            );
                            return;
                        }
                    },
                    Err(e) => {
                        write_line(
                            &mut stream,
                            json!({"ok":false,"error":format!("validate: {e}")}),
                        );
                        return;
                    }
                },
                Err(e) => {
                    write_line(
                        &mut stream,
                        json!({"ok":false,"error":format!("json: {e}")}),
                    );
                    return;
                }
            };
            request_reload(&mut stream, &tx, toml_text);
        }
        "config-set" => {
            let mut content = Vec::new();
            if stream.read_to_end(&mut content).is_err() || content.is_empty() {
                write_line(&mut stream, json!({"ok":false,"error":"empty body"}));
                return;
            }
            let toml_text = String::from_utf8_lossy(&content).into_owned();
            request_reload(&mut stream, &tx, toml_text);
        }
        "reload" => match std::fs::read_to_string(&config_path) {
            Ok(toml_text) => request_reload(&mut stream, &tx, toml_text),
            Err(e) => write_line(
                &mut stream,
                json!({"ok":false,"error":format!("read config: {e}")}),
            ),
        },
        other => write_line(
            &mut stream,
            json!({"ok":false,"error":format!("unknown cmd: {other}")}),
        ),
    }
}

fn request_reload(stream: &mut UnixStream, tx: &SyncSender<Req>, toml: String) {
    let (rtx, rrx) = std::sync::mpsc::sync_channel(1);
    if tx.send(Req::Reload { toml, reply: rtx }).is_err() {
        write_line(stream, json!({"ok":false,"error":"daemon loop gone"}));
        return;
    }
    match rrx.recv_timeout(Duration::from_secs(8)) {
        Ok(Ok(())) => write_line(stream, json!({"ok":true,"reloaded":true})),
        Ok(Err(e)) => write_line(stream, json!({"ok":false,"error":e})),
        Err(_) => write_line(stream, json!({"ok":false,"error":"reload timeout"})),
    }
}

pub fn client_main(sock: &PathBuf, req: &str, body: Option<&[u8]>, raw_field: Option<&str>) -> i32 {
    let mut s = match UnixStream::connect(sock) {
        Ok(s) => s,
        Err(_) => {
            println!(
                "{}",
                json!({"ok":false,"error":"daemon not running","daemon":false})
            );
            return 1;
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    if s.write_all(req.as_bytes()).is_err() {
        return 1;
    }
    if let Some(b) = body {
        if s.write_all(b).is_err() {
            return 1;
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = String::new();
    if s.read_to_string(&mut out).is_err() {
        return 1;
    }
    let Ok(resp) = serde_json::from_str::<Value>(out.trim()) else {
        eprintln!("bad response: {}", out.trim());
        return 1;
    };
    match raw_field {
        Some(field) => match resp.get(field).and_then(Value::as_str) {
            Some(v) => {
                print!("{}", v);
                0
            }
            None => {
                println!("{}", serde_json::to_string(&resp).unwrap_or_default());
                1
            }
        },
        None => {
            println!("{}", serde_json::to_string(&resp).unwrap_or_default());
            if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                0
            } else {
                1
            }
        }
    }
}

pub fn drain_reload(rx: &Receiver<Req>, apply: &mut dyn FnMut(&str) -> Result<(), String>) {
    while let Ok(req) = rx.try_recv() {
        let Req::Reload { toml, reply } = req;
        let result = apply(&toml);
        let _ = reply.send(result);
    }
}
