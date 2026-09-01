// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

pub const RING_CAP: usize = 2000;
pub const FILE_CAP: u64 = 2 * 1024 * 1024;
pub const KEEP_TAIL: u64 = 512 * 1024;

#[derive(Clone, Serialize, Deserialize)]
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
}

impl Ev {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

struct Inner {
    ring: VecDeque<Ev>,
    last_seq: u64,
    path: PathBuf,
    file: Option<File>,
    pushes_since_rotate: usize,
}

pub struct Store(Mutex<Inner>);

static GLOBAL: OnceLock<Store> = OnceLock::new();

pub fn init(persist_dir: &Path) {
    let path = persist_dir.join("events.jsonl");
    let _ = std::fs::create_dir_all(persist_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(persist_dir, std::fs::Permissions::from_mode(0o700));
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok();
    let last_seq = scan_last_seq(&path);
    let _ = GLOBAL.set(Store(Mutex::new(Inner {
        ring: VecDeque::new(),
        last_seq,
        path,
        file,
        pushes_since_rotate: 0,
    })));
}

pub fn push(mut ev: Ev) {
    if let Some(store) = GLOBAL.get() {
        store.0.lock().push(&mut ev);
    }
}

pub fn query(after: u64, limit: usize) -> Vec<Ev> {
    GLOBAL
        .get()
        .map(|s| s.0.lock().query(after, limit))
        .unwrap_or_default()
}

pub fn newest_seq() -> u64 {
    GLOBAL.get().map(|s| s.0.lock().last_seq).unwrap_or(0)
}

pub fn file_len() -> u64 {
    GLOBAL
        .get()
        .map(|s| {
            let g = s.0.lock();
            std::fs::metadata(&g.path).map(|m| m.len()).unwrap_or(0)
        })
        .unwrap_or(0)
}

pub fn clear() {
    if let Some(store) = GLOBAL.get() {
        store.0.lock().clear();
    }
}

impl Inner {
    fn push(&mut self, ev: &mut Ev) {
        self.last_seq += 1;
        ev.seq = self.last_seq;
        if let Some(f) = self.file.as_mut() {
            let _ = f.write_all(ev.to_json().as_bytes());
            let _ = f.write_all(b"\n");
            let _ = f.flush();
        }
        self.ring.push_back(ev.clone());
        while self.ring.len() > RING_CAP {
            self.ring.pop_front();
        }
        self.pushes_since_rotate += 1;
        if self.pushes_since_rotate >= 64 {
            self.pushes_since_rotate = 0;
            self.rotate_if_needed();
        }
    }

    fn query(&mut self, after: u64, limit: usize) -> Vec<Ev> {
        let covered = self
            .ring
            .front()
            .map(|e| e.seq <= after + 1)
            .unwrap_or(false);
        let mut out: Vec<Ev> = if covered {
            self.ring
                .iter()
                .filter(|e| e.seq > after)
                .cloned()
                .collect()
        } else {
            read_tail(&self.path, KEEP_TAIL)
                .map(|c| {
                    c.lines()
                        .filter_map(|l| serde_json::from_str::<Ev>(l).ok())
                        .filter(|e| e.seq > after)
                        .collect()
                })
                .unwrap_or_default()
        };
        if out.len() > limit {
            let start = out.len() - limit;
            out = out.split_off(start);
        }
        out
    }

    fn clear(&mut self) {
        self.ring.clear();
        if let Ok(f) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
        {
            self.file = Some(f);
        }
    }

    fn rotate_if_needed(&mut self) {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return;
        };
        if meta.len() < FILE_CAP {
            return;
        }
        let Ok(tail) = read_tail(&self.path, KEEP_TAIL) else {
            return;
        };
        let start = tail.find('\n').map(|i| i + 1).unwrap_or(tail.len());
        if std::fs::write(&self.path, &tail[start..]).is_ok() {
            self.file = OpenOptions::new().append(true).open(&self.path).ok();
        }
    }
}

fn read_tail(path: &Path, n: u64) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > n {
        f.seek(SeekFrom::End(-(n as i64)))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn scan_last_seq(path: &Path) -> u64 {
    read_tail(path, 4096)
        .map(|t| {
            t.lines()
                .rev()
                .find_map(|l| serde_json::from_str::<Ev>(l).ok().map(|e| e.seq))
                .unwrap_or(0)
        })
        .unwrap_or(0)
}
