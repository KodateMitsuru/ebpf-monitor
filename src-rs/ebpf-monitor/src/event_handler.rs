// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::HashMap;

use ebpf_monitor_common::PrintEvent;
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
    let file_op = e.op();
    let name = match file_op {
        ebpf_monitor_common::FileOp::Create => "create".to_string(),
        ebpf_monitor_common::FileOp::Mkdir => "mkdir".to_string(),
        ebpf_monitor_common::FileOp::Rename => "rename".to_string(),
        ebpf_monitor_common::FileOp::Unlink => "unlink".to_string(),
        _ => nr_names.get(&e.syscall_nr).cloned().unwrap_or_else(|| "?".into()),
    };
    let pkg = uid_names.get(&e.uid).cloned().unwrap_or_else(|| "-".into());
    let (ts, epoch_ms) = now();
    let file_str = cstr(&e.fname).to_string();
    let old_str = cstr(&e.old_fname).to_string();
    // file_id via inode+dev
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&file_str)
            .or_else(|_| if !old_str.is_empty() { std::fs::metadata(&old_str) } else { Err(std::io::Error::from(std::io::ErrorKind::NotFound)) })
            .map(|m| (m.dev(), m.ino()))
            .unwrap_or((0, 0))
    };

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
        file: file_str.clone(),
        cmd: read_cmdline(e.pid),
        old_file: old_str.clone(),
        dev,
        ino,
        file_id: if ino != 0 { (dev << 32) ^ ino } else { 0 },
        prev_hash: String::new(),
        hash: String::new(),
    });

    if e.watched != 0 {
        if !old_str.is_empty() {
            crate::log::info!(
                "WATCH {} ret={} pid={} uid={} pkg={} comm={} flags=0x{:x} {} -> {}",
                name, e.ret, e.pid, e.uid, pkg, cstr(&e.comm), e.sflags, old_str, file_str
            );
        } else {
            crate::log::info!(
                "WATCH {} ret={} pid={} uid={} pkg={} comm={} flags=0x{:x} file={}",
                name, e.ret, e.pid, e.uid, pkg, cstr(&e.comm), e.sflags, file_str
            );
        }
    } else if crate::log::verbosity() >= 2 {
        if !old_str.is_empty() {
            crate::log::info!(
                "print {} ret={} pid={} uid={} comm={} {} -> {}",
                name, e.ret, e.pid, e.uid, cstr(&e.comm), old_str, file_str
            );
        } else {
            crate::log::info!(
                "print {} ret={} pid={} uid={} comm={} file={}",
                name, e.ret, e.pid, e.uid, cstr(&e.comm), file_str
            );
        }

    }
}