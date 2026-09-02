// SPDX-License-Identifier: GPL-3.0-or-later
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use automerge::transaction::Transactable;
use automerge::{Automerge, ObjType, ReadDoc, ROOT};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};



#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ev {
    pub seq: u64,
    pub ts: String,
    pub epoch_ms: i64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: String,
    pub pkg: String,
    pub op: String,
    pub ret: i64,
    pub flags: u32,
    pub file: String,
    #[serde(default)]
    pub cmd: String,
    #[serde(default)]
    pub old_file: String,
    #[serde(default)]
    pub dev: u64,
    #[serde(default)]
    pub ino: u64,
    #[serde(default)]
    pub file_id: u64,
    #[serde(default)]
    pub prev_hash: String,
    pub hash: String,
}

impl Ev {
    pub fn to_json(&self) -> String { serde_json::to_string(self).unwrap_or_default() }
    pub fn file_id_computed(&self) -> u64 {
        if self.file_id != 0 { self.file_id } else if self.ino != 0 { (self.dev << 32) ^ self.ino } else { use std::hash::{Hash, Hasher}; let mut h = std::collections::hash_map::DefaultHasher::new(); self.file.hash(&mut h); h.finish() }
    }
}

struct Inner {
    doc: Automerge,
    events: automerge::ObjId,
    path: PathBuf,
}
pub struct Store(Mutex<Inner>);
static GLOBAL: OnceLock<Store> = OnceLock::new();

fn hash_of(s: &str) -> String { blake3::hash(s.as_bytes()).to_hex().to_string() }

pub fn init(persist_dir: &Path) {
    let _ = std::fs::create_dir_all(persist_dir);
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(persist_dir, std::fs::Permissions::from_mode(0o700)); }
    let path = persist_dir.join("forest.bin");
    let mut doc = if path.exists() { std::fs::read(&path).ok().and_then(|b| Automerge::load(&b).ok()).unwrap_or_else(Automerge::new) } else { Automerge::new() };
    let events = match doc.get(ROOT, "events").unwrap_or(None) {
        Some((v, id)) if v.is_object() => id,
        _ => { let mut tx = doc.transaction(); let id = tx.put_object(ROOT, "events", ObjType::List).unwrap(); tx.commit(); id }
    };
    let _ = GLOBAL.set(Store(Mutex::new(Inner { doc, events, path })));
}

pub fn push(mut ev: Ev) {
    let Some(s) = GLOBAL.get() else { return };
    let mut g = s.0.lock();
    let fid = ev.file_id_computed();
    ev.file_id = fid;
    let prev_hash = {
        let len = g.doc.length(&g.events);
        if len == 0 { String::new() } else {
            g.doc.get(&g.events, len - 1).ok().flatten().and_then(|(v, id)| {
                if v.is_object() { g.doc.get(&id, "hash").ok().flatten().map(|(vv, _)| vv.to_str().map(|s| s.to_string()).unwrap_or_default()) } else { None }
            }).unwrap_or_default()
        }
    };
    ev.prev_hash = prev_hash.clone();
    ev.hash = hash_of(&format!("{}|{}|{}|{}|{}", fid, ev.op, ev.file, ev.epoch_ms, prev_hash));
    let events_id = g.events.clone();
    let mut tx = g.doc.transaction();
    let idx = tx.length(&events_id);
    let obj = tx.insert_object(&events_id, idx, ObjType::Map).unwrap();
    tx.put(&obj, "hash", ev.hash.clone()).unwrap();
    tx.put(&obj, "prev_hash", ev.prev_hash.clone()).unwrap();
    tx.put(&obj, "ts", ev.ts.clone()).unwrap();
    tx.put(&obj, "epoch_ms", ev.epoch_ms).unwrap();
    tx.put(&obj, "pid", ev.pid as i64).unwrap();
    tx.put(&obj, "tid", ev.tid as i64).unwrap();
    tx.put(&obj, "uid", ev.uid as i64).unwrap();
    tx.put(&obj, "comm", ev.comm.clone()).unwrap();
    tx.put(&obj, "pkg", ev.pkg.clone()).unwrap();
    tx.put(&obj, "op", ev.op.clone()).unwrap();
    tx.put(&obj, "ret", ev.ret).unwrap();
    tx.put(&obj, "flags", ev.flags as i64).unwrap();
    tx.put(&obj, "file", ev.file.clone()).unwrap();
    tx.put(&obj, "cmd", ev.cmd.clone()).unwrap();
    tx.put(&obj, "old_file", ev.old_file.clone()).unwrap();
    tx.put(&obj, "dev", ev.dev as i64).unwrap();
    tx.put(&obj, "ino", ev.ino as i64).unwrap();
    tx.put(&obj, "file_id", fid as i64).unwrap();
    tx.put(&obj, "seq", tx.length(&events_id) as i64).unwrap();
    if tx.length(&events_id) > 10000 {
        let _ = tx.delete(&events_id, 0);
    }
    tx.commit();
    let bytes = g.doc.save();
    let path = g.path.clone();
    drop(g);
    let _ = std::fs::write(path, bytes);
}

pub fn query(_after: u64, limit: usize) -> Vec<Ev> {
    let Some(s) = GLOBAL.get() else { return Vec::new() };
    let g = s.0.lock();
    let len = g.doc.length(&g.events);
    let start = len.saturating_sub(limit);
    let mut out = Vec::new();
    for i in start..len {
        if let Ok(Some((v, obj))) = g.doc.get(&g.events, i) {
            if !v.is_object() { continue; }
            let get_str = |k: &str| g.doc.get(&obj, k).ok().flatten().and_then(|(vv, _)| vv.to_str().map(|s| s.to_string())).unwrap_or_default();
            let get_i64 = |k: &str| g.doc.get(&obj, k).ok().flatten().and_then(|(vv, _)| vv.to_i64()).unwrap_or(0);
            out.push(Ev {
                hash: get_str("hash"), prev_hash: get_str("prev_hash"), ts: get_str("ts"), epoch_ms: get_i64("epoch_ms"),
                pid: get_i64("pid") as u32, tid: get_i64("tid") as u32, uid: get_i64("uid") as u32,
                comm: get_str("comm"), pkg: get_str("pkg"), op: get_str("op"), ret: get_i64("ret"),
                flags: get_i64("flags") as u32, file: get_str("file"), cmd: get_str("cmd"), old_file: get_str("old_file"),
                dev: get_i64("dev") as u64, ino: get_i64("ino") as u64, file_id: get_i64("file_id") as u64,
                seq: get_i64("seq") as u64,
            });
        }
    }
    out
}

pub fn newest_seq() -> u64 { 0 }
pub fn file_len() -> u64 { GLOBAL.get().and_then(|s| std::fs::metadata(&s.0.lock().path).ok().map(|m| m.len())).unwrap_or(0) }
pub fn clear() {
    let Some(s) = GLOBAL.get() else { return };
    let mut g = s.0.lock();
    let mut doc = Automerge::new();
    let events = { let mut tx = doc.transaction(); let id = tx.put_object(ROOT, "events", ObjType::List).unwrap(); tx.commit(); id };
    g.doc = doc;
    g.events = events;
    let bytes = g.doc.save();
    let path = g.path.clone();
    drop(g);
    let _ = std::fs::write(path, bytes);
}
pub fn save_bytes() -> Vec<u8> { GLOBAL.get().map(|s| s.0.lock().doc.save()).unwrap_or_default() }
pub fn load_bytes(b: &[u8]) {
    let Some(s) = GLOBAL.get() else { return };
    let mut g = s.0.lock();
    if let Ok(mut other) = Automerge::load(b) { let _ = g.doc.merge(&mut other); let bytes = g.doc.save(); let path = g.path.clone(); drop(g); let _ = std::fs::write(path, bytes); }
}
