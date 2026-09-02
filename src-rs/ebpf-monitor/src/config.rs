// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

use ebpf_monitor_common::{SyscallArgInfo, SYSCALL_FLAG_PRINT, SYSCALL_FLAG_WATCH, WATCH_BASE_MAX};

use crate::catalog::{default_groups, syscall_groups, syscalls};

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("TOML ser: {0}")]
    Ser(#[from] toml::ser::Error),
    #[error("{0}")]
    Validation(String),
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Whitelist {
    #[serde(default)]
    pub uid: Vec<u32>,
    #[serde(default)]
    pub pid: Vec<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PrintConfig {
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WatchConfig {
    pub basenames: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// User-editable fields.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub whitelist: Whitelist,
    #[serde(default)]
    pub watch: Option<WatchConfig>,
    #[serde(default)]
    pub print: Option<PrintConfig>,
}

#[derive(Debug)]
pub struct ValidatedConfig {
    pub syscall_args_64: Vec<(u32, SyscallArgInfo)>,
    pub syscall_args_32: Vec<(u32, SyscallArgInfo)>,
    pub watch_basenames: Vec<String>,
}

fn resolve_str_register(args: &[crate::catalog::ArgDef], param: Option<&str>) -> Option<u32> {
    use crate::catalog::ArgType;
    if let Some(name) = param {
        if let Some(a) = args.iter().find(|a| a.name == name && a.arg_type == ArgType::Str) {
            return Some(a.reg);
        }
    }
    args.iter().find(|a| a.arg_type == ArgType::Str).map(|a| a.reg)
}

fn resolve_int_register(args: &[crate::catalog::ArgDef], name: &str) -> Option<u32> {
    use crate::catalog::ArgType;
    args.iter().find(|a| a.name == name && a.arg_type == ArgType::Int).map(|a| a.reg)
}

struct Active<'a> {
    flags: u32,
    watch_param: Option<&'a str>,
    watch_set: bool,
    fl_param: Option<&'a str>,
    fl_mask: u32,
}

const PID_TEMP: &str = "/data/local/tmp/ebpf-monitor-pid.json";

fn load_pid_temp() -> Vec<u32> {
    std::fs::read_to_string(PID_TEMP)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_pid_temp(pid: &[u32]) -> Result<(), ConfigError> {
    let dir = std::path::Path::new(PID_TEMP).parent().unwrap();
    let _ = std::fs::create_dir_all(dir);
    let data = serde_json::to_string(pid).unwrap();
    std::fs::write(PID_TEMP, data)?;
    Ok(())
}

impl Config {
    #[allow(dead_code)]
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Load persistent keys from KSU and volatile pid from temp.
    pub fn load() -> Self {
        let mut cfg = Self::factory_default();
        let get = |k: &str| {
            std::process::Command::new("ksud")
                .args(["module", "config", "get", k])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        };
        if let Some(v) = get("watch.basenames") {
            if let Ok(a) = serde_json::from_str::<Vec<String>>(&v) {
                cfg.watch.get_or_insert_with(|| WatchConfig { basenames: vec![], groups: vec![] }).basenames = a;
            }
        }
        if let Some(v) = get("watch.groups") {
            if let Ok(a) = serde_json::from_str::<Vec<String>>(&v) {
                cfg.watch.get_or_insert_with(|| WatchConfig { basenames: vec![], groups: vec![] }).groups = a;
            }
        }
        if let Some(v) = get("whitelist.uid") {
            if let Ok(a) = serde_json::from_str::<Vec<u32>>(&v) {
                cfg.whitelist.uid = a;
            }
        }
        // pid is volatile, not in KSU
        cfg.whitelist.pid = load_pid_temp();
        if let Some(v) = get("print.groups") {
            if let Ok(a) = serde_json::from_str::<Vec<String>>(&v) {
                if a.is_empty() { cfg.print = None; } else { cfg.print = Some(PrintConfig { groups: a }); }
            }
        }
        cfg
    }

    pub fn save(&self) -> Result<(), ConfigError> {
        let set = |k: &str, v: &str| -> Result<(), ConfigError> {
            let out = std::process::Command::new("ksud")
                .args(["module", "config", "set", k, v])
                .output()
                .map_err(|e| ConfigError::Validation(format!("ksud: {e}")))?;
            if !out.status.success() {
                return Err(ConfigError::Validation(String::from_utf8_lossy(&out.stderr).to_string()));
            }
            Ok(())
        };
        if let Some(w) = &self.watch {
            set("watch.basenames", &serde_json::to_string(&w.basenames).unwrap())?;
            set("watch.groups", &serde_json::to_string(&w.groups).unwrap())?;
        } else {
            set("watch.basenames", "[]")?;
            set("watch.groups", &serde_json::to_string(&default_groups()).unwrap())?;
        }
        set("whitelist.uid", &serde_json::to_string(&self.whitelist.uid).unwrap())?;
        // pid goes to temp, not KSU
        save_pid_temp(&self.whitelist.pid)?;
        if let Some(p) = &self.print {
            set("print.groups", &serde_json::to_string(&p.groups).unwrap())?;
        } else {
            set("print.groups", "[]")?;
        }
        Ok(())
    }

    pub fn factory_default() -> Self {
        Self {
            whitelist: Whitelist { uid: vec![], pid: vec![] },
            watch: Some(WatchConfig { basenames: vec![], groups: default_groups() }),
            print: None,
        }
    }

    #[allow(dead_code)]
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(s).map_err(|e| ConfigError::Validation(format!("json: {e}")))
    }
    #[allow(dead_code)]
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string(self).map_err(|e| ConfigError::Validation(format!("json ser: {e}")))
    }
    #[allow(dead_code)]
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(content)?)
    }
    #[allow(dead_code)]
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<ValidatedConfig, ConfigError> {
        let err = |msg: String| ConfigError::Validation(msg);
        let blank = || Active { flags: 0, watch_param: None, watch_set: false, fl_param: None, fl_mask: 0 };
        let syscalls = syscalls();
        let groups = syscall_groups();
        let syscall_map: HashMap<&str, &crate::catalog::SyscallDef> = syscalls.iter().map(|s| (s.name.as_str(), s)).collect();
        let group_map: HashMap<&str, &[String]> = groups.iter().map(|g| (g.name.as_str(), g.syscalls.as_slice())).collect();
        let mut active: HashMap<&str, Active> = HashMap::new();
        if let Some(print) = &self.print {
            for gname in &print.groups {
                let syscalls = group_map.get(gname.as_str()).ok_or_else(|| err(format!("[print]: unknown group '{gname}'")))?;
                for sname in *syscalls {
                    active.entry(sname.as_str()).or_insert_with(blank).flags |= SYSCALL_FLAG_PRINT;
                }
            }
        }
        if let Some(watch) = &self.watch {
            for gname in &watch.groups {
                let group = groups.iter().find(|g| &g.name == gname).ok_or_else(|| err(format!("[watch]: unknown group '{gname}'")))?;
                if group.watch_flag_mask.is_some() != group.watch_flag_param.is_some() {
                    return Err(err(format!("[watch]: group '{gname}': watch_flag_mask 与 watch_flag_param 必须成对出现")));
                }
                for sname in &group.syscalls {
                    let e = active.entry(sname.as_str()).or_insert_with(blank);
                    e.flags |= SYSCALL_FLAG_WATCH;
                    let wparam = group.watch_param.as_deref();
                    if e.watch_set && (e.watch_param.is_some() != wparam.is_some() || (wparam.is_some() && e.watch_param != wparam)) {
                        return Err(err(format!("syscall '{sname}': conflicting watch params")));
                    }
                    e.watch_param = e.watch_param.or(wparam);
                    e.watch_set = true;
                    let fparam = group.watch_flag_param.as_deref();
                    if e.fl_param.is_some() {
                        if e.fl_param != fparam || e.fl_mask != group.watch_flag_mask.unwrap_or(0) {
                            return Err(err(format!("syscall '{sname}': conflicting watch flag filters")));
                        }
                    } else {
                        e.fl_param = fparam;
                        e.fl_mask = group.watch_flag_mask.unwrap_or(0);
                    }
                }
            }
        }
        let mut args_64 = Vec::new();
        let mut args_32 = Vec::new();
        for (&sname, a) in &active {
            let def = syscall_map.get(sname).ok_or_else(|| err(format!("undefined syscall '{sname}'")))?;
            if let Some(nr64) = def.nr.arm64 {
                let reg = resolve_str_register(&def.arm64, a.watch_param).ok_or_else(|| err(format!("syscall '{sname}' arm64: no str param")))?;
                let fl_reg = match a.fl_param {
                    Some(p) => resolve_int_register(&def.arm64, p).ok_or_else(|| err(format!("syscall '{sname}' arm64: no int param '{p}'")))?,
                    None => 0,
                };
                args_64.push((nr64, SyscallArgInfo { str_reg_idx: reg, flags: a.flags, fl_reg_idx: fl_reg, fl_mask: a.fl_mask }));
            }
            if let Some(nr32) = def.nr.arm32 {
                let reg = resolve_str_register(&def.arm32, a.watch_param).ok_or_else(|| err(format!("syscall '{sname}' arm32: no str param")))?;
                let fl_reg = match a.fl_param {
                    Some(p) => resolve_int_register(&def.arm32, p).ok_or_else(|| err(format!("syscall '{sname}' arm32: no int param '{p}'")))?,
                    None => 0,
                };
                args_32.push((nr32, SyscallArgInfo { str_reg_idx: reg, flags: a.flags, fl_reg_idx: fl_reg, fl_mask: a.fl_mask }));
            }
        }
        let mut watch_basenames = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        if let Some(watch) = &self.watch {
            for b in &watch.basenames {
                let n = b.len();
                if n == 0 || n >= WATCH_BASE_MAX {
                    return Err(err(format!("[watch]: basename '{b}' 长度须在 1..{} 字节", WATCH_BASE_MAX - 1)));
                }
                if !seen.insert(b.as_str()) { continue; }
                watch_basenames.push(b.clone());
            }
        }
        args_64.sort_by_key(|(nr, _)| *nr);
        args_32.sort_by_key(|(nr, _)| *nr);
        Ok(ValidatedConfig { syscall_args_64: args_64, syscall_args_32: args_32, watch_basenames })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use ebpf_monitor_common::SYSCALL_FLAG_WATCH;

    #[test]
    fn factory_config_validates() {
        let cfg = Config::factory_default();
        let v = cfg.validate().expect("validate factory config");
        let openat = v.syscall_args_64.iter().find(|(nr, _)| *nr == 56).expect("openat arm64 entry");
        assert_ne!(openat.1.flags & SYSCALL_FLAG_WATCH, 0);
        assert_eq!(openat.1.fl_reg_idx, 2);
        assert_eq!(openat.1.fl_mask, 0x40);
        assert_eq!(openat.1.str_reg_idx, 1);
        let renameat = v.syscall_args_64.iter().find(|(nr, _)| *nr == 38).expect("renameat arm64 entry");
        assert_ne!(renameat.1.flags & SYSCALL_FLAG_WATCH, 0);
        assert_eq!(renameat.1.fl_mask, 0);
        assert_eq!(renameat.1.str_reg_idx, 3);
        assert!(!v.syscall_args_64.iter().any(|(nr, _)| *nr == 8));
        let creat = v.syscall_args_32.iter().find(|(nr, _)| *nr == 8).expect("creat arm32 entry");
        assert_ne!(creat.1.flags & SYSCALL_FLAG_WATCH, 0);
        assert_eq!(creat.1.str_reg_idx, 0);
        let openat32 = v.syscall_args_32.iter().find(|(nr, _)| *nr == 322).expect("openat arm32 entry");
        assert_eq!(openat32.1.str_reg_idx, 1);
        assert_eq!(openat32.1.fl_reg_idx, 2);
        assert_eq!(openat32.1.fl_mask, 0x40);
        assert!(v.watch_basenames.is_empty());
    }

    #[test]
    fn invalid_group_rejected() {
        let mut cfg = Config::factory_default();
        cfg.watch.as_mut().unwrap().groups = vec!["nonexistent".into()];
        assert!(cfg.validate().is_err());
    }
}
