// SPDX-License-Identifier: GPL-3.0-or-later
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::Ebpf;
use aya::Pod;

use crate::config::{Config, ValidatedConfig};
use crate::types::{SyscallArgInfo, WATCH_BASE_MAX};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ArgInfo {
    pub str_reg_idx: u32,
    pub flags: u32,
    pub fl_reg_idx: u32,
    pub fl_mask: u32,
}
unsafe impl Pod for ArgInfo {}

impl From<&SyscallArgInfo> for ArgInfo {
    fn from(v: &SyscallArgInfo) -> Self {
        Self {
            str_reg_idx: v.str_reg_idx,
            flags: v.flags,
            fl_reg_idx: v.fl_reg_idx,
            fl_mask: v.fl_mask,
        }
    }
}

pub struct Maps {
    pub args64: AyaHashMap<MapData, u32, ArgInfo>,
    pub args32: AyaHashMap<MapData, u32, ArgInfo>,
    pub watch: AyaHashMap<MapData, [u8; WATCH_BASE_MAX], u8>,
    pub pid_wl: AyaHashMap<MapData, u32, u8>,
    pub uid_wl: AyaHashMap<MapData, u32, u8>,
    pub events: RingBuf<MapData>,
}

fn take_hash<K, V>(bpf: &mut Ebpf, name: &str) -> Result<AyaHashMap<MapData, K, V>, String>
where
    K: Pod + Clone,
    V: Pod + Clone,
{
    let map = bpf
        .take_map(name)
        .ok_or_else(|| format!("map '{name}' not found"))?;
    AyaHashMap::try_from(map).map_err(|e| format!("'{name}': {e}"))
}

impl Maps {
    pub fn take(bpf: &mut Ebpf) -> Result<Self, String> {
        Ok(Self {
            args64: take_hash(bpf, "ARGS64")?,
            args32: take_hash(bpf, "ARGS32")?,
            watch: take_hash(bpf, "WATCH_RULES")?,
            pid_wl: take_hash(bpf, "PID_WL")?,
            uid_wl: take_hash(bpf, "UID_WL")?,
            events: RingBuf::try_from(
                bpf.take_map("EVENTS")
                    .ok_or_else(|| "map EVENTS not found".to_string())?,
            )
            .map_err(|e| format!("EVENTS: {e}"))?,
        })
    }
}

pub fn load_syscall_args(maps: &mut Maps, validated: &ValidatedConfig) -> Result<(), String> {
    for (nr, info) in &validated.syscall_args_64 {
        maps.args64
            .insert(nr, &ArgInfo::from(info), 0)
            .map_err(|e| format!("args64[{nr}]: {e}"))?;
    }
    for (nr, info) in &validated.syscall_args_32 {
        maps.args32
            .insert(nr, &ArgInfo::from(info), 0)
            .map_err(|e| format!("args32[{nr}]: {e}"))?;
    }
    crate::log::info!(
        "Loaded {} 64-bit + {} 32-bit syscall entries",
        validated.syscall_args_64.len(),
        validated.syscall_args_32.len()
    );
    Ok(())
}

pub fn load_watch_rules(maps: &mut Maps, validated: &ValidatedConfig) -> Result<(), String> {
    for b in &validated.watch_basenames {
        let mut key = [0u8; WATCH_BASE_MAX];
        key[WATCH_BASE_MAX - b.len()..].copy_from_slice(b.as_bytes());
        maps.watch
            .insert(&key, &1u8, 0)
            .map_err(|e| format!("watch[{b}]: {e}"))?;
    }
    if !validated.watch_basenames.is_empty() {
        crate::log::info!("Loaded watch basenames: {:?}", validated.watch_basenames);
    }
    Ok(())
}

pub fn load_whitelist(maps: &mut Maps, config: &Config) -> Result<(), String> {
    for &uid in &config.whitelist.uid {
        maps.uid_wl
            .insert(&uid, &1u8, 0)
            .map_err(|e| format!("uid_wl: {e}"))?;
    }
    for &pid in &config.whitelist.pid {
        maps.pid_wl
            .insert(&pid, &1u8, 0)
            .map_err(|e| format!("pid_wl: {e}"))?;
    }
    crate::log::info!(
        "Loaded whitelist: {} uids, {} pids",
        config.whitelist.uid.len(),
        config.whitelist.pid.len()
    );
    Ok(())
}

fn clear_hash<K, V>(map: &mut AyaHashMap<MapData, K, V>)
where
    K: Pod + Clone,
    V: Pod + Clone,
{
    let keys: Vec<K> = map.keys().flatten().collect();
    for k in &keys {
        let _ = map.remove(k);
    }
}

pub fn reload(maps: &mut Maps, config: &Config) -> Result<(), String> {
    clear_hash(&mut maps.args64);
    clear_hash(&mut maps.args32);
    clear_hash(&mut maps.watch);
    let validated = config.validate().map_err(|e| e.to_string())?;
    load_syscall_args(maps, &validated)?;
    load_watch_rules(maps, &validated)?;
    Ok(())
}
