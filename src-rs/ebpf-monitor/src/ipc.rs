// SPDX-License-Identifier: GPL-3.0-or-later
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

use serde_json::{json, Value};

use crate::events;

pub enum Req {
    Reload { reply: SyncSender<Result<(), String>> },
}

pub struct Ipc {
    pub socket: PathBuf,
    tx: SyncSender<Req>,
}

impl Ipc {
    pub fn new(persist_dir: PathBuf, tx: SyncSender<Req>) -> Self {
        Self { socket: persist_dir.join("ctl.sock"), tx }
    }
    pub fn bind(&self) -> std::io::Result<UnixListener> {
        if self.socket.exists() { let _ = std::fs::remove_file(&self.socket); }
        let l = UnixListener::bind(&self.socket)?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&self.socket, std::fs::Permissions::from_mode(0o600)); }
        Ok(l)
    }
    pub fn serve(&self, listener: UnixListener) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() { if let Ok(stream) = conn { let tx = tx.clone(); std::thread::spawn(move || serve_conn(stream, tx)); } }
        });
    }
}

fn write_line(stream: &mut UnixStream, v: Value) {
    let s = serde_json::to_string(&v).unwrap_or_else(|_| "{}".into());
    let _ = stream.write_all(s.as_bytes());
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

fn serve_conn(mut stream: UnixStream, tx: SyncSender<Req>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut line = String::new();
    {
        let mut b = [0u8; 1];
        loop {
            match stream.read(&mut b) {
                Ok(0) => return,
                Ok(_) => { line.push(b[0] as char); if b[0]==b'\n' { break; } if line.len()>8192 { return; } }
                Err(_) => return,
            }
        }
    }
    let Ok(req) = serde_json::from_str::<Value>(line.trim_end()) else { return; };
    let cmd = req.get("cmd").and_then(Value::as_str).unwrap_or_default().to_string();
    match cmd.as_str() {
        "ping" => write_line(&mut stream, json!({"ok":true,"pong":true})),
        "status" => {
            let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default();
            write_line(&mut stream, json!({"ok":true,"newest": events::newest_seq(),"kernel":kernel,"btf": Path::new("/sys/kernel/btf/vmlinux").exists(),"events_bytes": events::file_len(),"daemon_pid": std::process::id()}));
        }
        "events" => {
            let after = req.get("after").and_then(Value::as_u64).unwrap_or(0);
            let limit = req.get("limit").and_then(Value::as_u64).unwrap_or(500).min(2000) as usize;
            let evs: Vec<Value> = events::query(after, limit).iter().filter_map(|e| serde_json::from_str(&e.to_json()).ok()).collect();
            write_line(&mut stream, json!({"ok":true,"events":evs}));
        }
        "clear" => { events::clear(); write_line(&mut stream, json!({"ok":true,"cleared":true})); }
        "config-get" | "get-config" => {
            let cfg = crate::config::Config::load();
            match serde_json::to_value(&cfg) {
                Ok(v) => write_line(&mut stream, json!({"ok":true,"config":v})),
                Err(e) => write_line(&mut stream, json!({"ok":false,"error":format!("tojson: {e}")})),
            }
        }
        "set-config" | "config-set" => {
            let mut content = Vec::new();
            if stream.read_to_end(&mut content).is_err() || content.is_empty() {
                write_line(&mut stream, json!({"ok":false,"error":"empty body"})); return;
            }
            let cfg: Result<crate::config::Config, _> = serde_json::from_slice(&content);
            match cfg {
                Ok(c) => {
                    if let Err(e) = c.validate() { write_line(&mut stream, json!({"ok":false,"error":format!("validate: {e}")})); return; }
                    if let Err(e) = c.save() { write_line(&mut stream, json!({"ok":false,"error":format!("ksu save: {e}")})); return; }
                }
                Err(e) => write_line(&mut stream, json!({"ok":false,"error":format!("json: {e}")})),
            }
        }
        "reload" => request_reload(&mut stream, &tx),
        "sync" => {
            let mut body = Vec::new();
            let _ = stream.read_to_end(&mut body);
            if !body.is_empty() {
                let b64 = String::from_utf8_lossy(&body).trim().to_string();
                if let Ok(bytes) = base64_decode(&b64) { events::load_bytes(&bytes); }
            }
            let doc = events::save_bytes();
            let b64 = base64_encode(&doc);
            write_line(&mut stream, json!({"ok":true,"doc": b64}));
        }
        other => write_line(&mut stream, json!({"ok":false,"error":format!("unknown cmd: {other}")})),
    }
}

fn base64_encode(b: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity((b.len()+2)/3*4);
    let mut i = 0;
    while i < b.len() {
        let a = b[i] as u32; let bb = if i+1<b.len() { b[i+1] as u32 } else { 0 }; let c2 = if i+2<b.len() { b[i+2] as u32 } else { 0 };
        let n = (a<<16)|(bb<<8)|c2;
        o.push(ALPH[((n>>18)&63) as usize] as char); o.push(ALPH[((n>>12)&63) as usize] as char);
        if i+1<b.len() { o.push(ALPH[((n>>6)&63) as usize] as char); } else { o.push('='); }
        if i+2<b.len() { o.push(ALPH[(n&63) as usize] as char); } else { o.push('='); }
        i+=3;
    }
    o
}
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_matches('"');
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut buf: u32 = 0; let mut bits = 0;
    for &ch in bytes {
        let v = match ch { b'A'..=b'Z' => (ch-b'A') as u32, b'a'..=b'z' => (ch-b'a'+26) as u32, b'0'..=b'9' => (ch-b'0'+52) as u32, b'+' => 62, b'/' => 63, b'=' => break, _ => continue };
        buf = (buf<<6)|v; bits+=6;
        if bits>=8 { bits-=8; out.push(((buf>>bits)&0xFF) as u8); }
    }
    Ok(out)
}
fn request_reload(stream: &mut UnixStream, tx: &SyncSender<Req>) {
    let (rtx, rrx) = std::sync::mpsc::sync_channel(1);
    if tx.send(Req::Reload { reply: rtx }).is_err() { write_line(stream, json!({"ok":false,"error":"daemon loop gone"})); return; }
    match rrx.recv_timeout(Duration::from_secs(8)) {
        Ok(Ok(())) => write_line(stream, json!({"ok":true,"reloaded":true})),
        Ok(Err(e)) => write_line(stream, json!({"ok":false,"error":e})),
        Err(_) => write_line(stream, json!({"ok":false,"error":"reload timeout"})),
    }
}

pub fn drain_reload(rx: &Receiver<Req>, apply: &mut dyn FnMut() -> Result<(), String>) {
    while let Ok(req) = rx.try_recv() {
        match req { Req::Reload { reply } => { let r = apply(); let _ = reply.send(r); } }
    }
}
