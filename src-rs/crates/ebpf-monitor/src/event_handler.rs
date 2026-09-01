// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::HashMap;

use crate::types::PrintEvent;
use chrono::Local;

use crate::events::{self, Ev};

fn cstr(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..len]).unwrap_or("<invalid>")
}

fn now() -> (String, i64) {
    let t = Local::now();
    (t.format("%m-%d %H:%M:%S").to_string(), t.timestamp_millis())
}

fn read_cmdline(pid: u32) -> String {
    let Ok(bytes) = std::fs::read(format!("/proc/{}/cmdline", pid)) else {
        return String::new();
    };
    let joined = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let joined = joined.trim().to_string();
    if joined.chars().count() > 200 {
        let truncated: String = joined.chars().take(200).collect();
        format!("{}…", truncated)
    } else {
        joined
    }
}

pub fn handle(data: &[u8], nr_names: &HashMap<u32, String>, uid_names: &HashMap<u32, String>) {
    let mut e = PrintEvent::default();
    if plain::copy_from_bytes(&mut e, data).is_err() {
        return;
    }
    let name = nr_names
        .get(&e.syscall_nr)
        .cloned()
        .unwrap_or_else(|| "?".into());
    let pkg = uid_names.get(&e.uid).cloned().unwrap_or_else(|| "-".into());
    let (ts, epoch_ms) = now();

    events::push(Ev {
        seq: 0,
        ts,
        epoch_ms,
        pid: e.pid,
        tid: e.tid,
        uid: e.uid,
        comm: cstr(&e.comm).to_string(),
        pkg: pkg.clone(),
        op: name.clone(),
        ret: e.ret,
        flags: e.sflags,
        file: cstr(&e.fname).to_string(),
        cmd: read_cmdline(e.pid),
    });

    if e.watched != 0 {
        crate::log::info!(
            "WATCH {} ret={} pid={} uid={} pkg={} comm={} flags=0x{:x} file={}",
            name,
            e.ret,
            e.pid,
            e.uid,
            pkg,
            cstr(&e.comm),
            e.sflags,
            cstr(&e.fname)
        );
    } else if crate::log::verbosity() >= 2 {
        crate::log::info!(
            "print {} ret={} pid={} uid={} comm={} file={}",
            name,
            e.ret,
            e.pid,
            e.uid,
            cstr(&e.comm),
            cstr(&e.fname)
        );
    }
}
