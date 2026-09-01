// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

use crate::types::{SyscallArgInfo, SYSCALL_FLAG_PRINT, SYSCALL_FLAG_WATCH, WATCH_BASE_MAX};

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

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub whitelist: Whitelist,
    #[serde(default)]
    pub syscall: Vec<SyscallDef>,
    #[serde(default)]
    pub syscall_groups: Vec<SyscallGroup>,
    #[serde(default)]
    pub print: Option<PrintConfig>,
    #[serde(default)]
    pub watch: Option<WatchConfig>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Whitelist {
    #[serde(default)]
    pub uid: Vec<u32>,
    #[serde(default)]
    pub pid: Vec<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallDef {
    pub name: String,
    pub nr: SyscallNr,
    #[serde(default)]
    pub arm64: Vec<ArgDef>,
    #[serde(default)]
    pub arm32: Vec<ArgDef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallNr {
    #[serde(default)]
    pub arm64: Option<u32>,
    #[serde(default)]
    pub arm32: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ArgDef {
    pub reg: u32,
    #[serde(rename = "type")]
    pub arg_type: ArgType,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ArgType {
    Str,
    Int,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyscallGroup {
    pub name: String,
    pub syscalls: Vec<String>,
    #[serde(default)]
    pub watch_param: Option<String>,
    #[serde(default)]
    pub watch_flag_param: Option<String>,
    #[serde(default)]
    pub watch_flag_mask: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrintConfig {
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WatchConfig {
    pub basenames: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug)]
pub struct ValidatedConfig {
    pub syscall_args_64: Vec<(u32, SyscallArgInfo)>,
    pub syscall_args_32: Vec<(u32, SyscallArgInfo)>,
    pub watch_basenames: Vec<String>,
}

fn find_str_reg(args: &[ArgDef], param: Option<&str>) -> Option<u32> {
    if let Some(name) = param {
        if let Some(a) = args
            .iter()
            .find(|a| a.name == name && a.arg_type == ArgType::Str)
        {
            return Some(a.reg);
        }
    }
    args.iter()
        .find(|a| a.arg_type == ArgType::Str)
        .map(|a| a.reg)
}

fn find_int_reg(args: &[ArgDef], name: &str) -> Option<u32> {
    args.iter()
        .find(|a| a.name == name && a.arg_type == ArgType::Int)
        .map(|a| a.reg)
}

struct Active<'a> {
    flags: u32,
    watch_param: Option<&'a str>,
    watch_set: bool,
    fl_param: Option<&'a str>,
    fl_mask: u32,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_str(&content)
    }

    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(content)?)
    }

    pub fn to_toml_str(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<ValidatedConfig, ConfigError> {
        let err = |msg: String| ConfigError::Validation(msg);
        let blank = || Active {
            flags: 0,
            watch_param: None,
            watch_set: false,
            fl_param: None,
            fl_mask: 0,
        };

        let syscall_map: HashMap<&str, &SyscallDef> =
            self.syscall.iter().map(|s| (s.name.as_str(), s)).collect();
        let group_map: HashMap<&str, &[String]> = self
            .syscall_groups
            .iter()
            .map(|g| (g.name.as_str(), g.syscalls.as_slice()))
            .collect();

        let mut active: HashMap<&str, Active> = HashMap::new();

        if let Some(print) = &self.print {
            for gname in &print.groups {
                let syscalls = group_map
                    .get(gname.as_str())
                    .ok_or_else(|| err(format!("[print]: unknown group '{gname}'")))?;
                for sname in *syscalls {
                    active.entry(sname.as_str()).or_insert_with(blank).flags |= SYSCALL_FLAG_PRINT;
                }
            }
        }

        if let Some(watch) = &self.watch {
            for gname in &watch.groups {
                let group = self
                    .syscall_groups
                    .iter()
                    .find(|g| &g.name == gname)
                    .ok_or_else(|| err(format!("[watch]: unknown group '{gname}'")))?;
                if group.watch_flag_mask.is_some() != group.watch_flag_param.is_some() {
                    return Err(err(format!(
                        "[watch]: group '{gname}': watch_flag_mask 与 watch_flag_param 必须成对出现"
                    )));
                }
                for sname in &group.syscalls {
                    let e = active.entry(sname.as_str()).or_insert_with(blank);
                    e.flags |= SYSCALL_FLAG_WATCH;

                    let wparam = group.watch_param.as_deref();
                    if e.watch_set
                        && (e.watch_param.is_some() != wparam.is_some()
                            || (wparam.is_some() && e.watch_param != wparam))
                    {
                        return Err(err(format!("syscall '{sname}': conflicting watch params")));
                    }
                    e.watch_param = e.watch_param.or(wparam);
                    e.watch_set = true;

                    let fparam = group.watch_flag_param.as_deref();
                    if e.fl_param.is_some() {
                        if e.fl_param != fparam || e.fl_mask != group.watch_flag_mask.unwrap_or(0) {
                            return Err(err(format!(
                                "syscall '{sname}': conflicting watch flag filters"
                            )));
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
            let def = syscall_map
                .get(sname)
                .ok_or_else(|| err(format!("undefined syscall '{sname}'")))?;

            if let Some(nr64) = def.nr.arm64 {
                let reg = find_str_reg(&def.arm64, a.watch_param)
                    .ok_or_else(|| err(format!("syscall '{sname}' arm64: no str param")))?;
                let fl_reg = match a.fl_param {
                    Some(p) => find_int_reg(&def.arm64, p).ok_or_else(|| {
                        err(format!("syscall '{sname}' arm64: no int param '{p}'"))
                    })?,
                    None => 0,
                };
                args_64.push((
                    nr64,
                    SyscallArgInfo {
                        str_reg_idx: reg,
                        flags: a.flags,
                        fl_reg_idx: fl_reg,
                        fl_mask: a.fl_mask,
                    },
                ));
            }

            if let Some(nr32) = def.nr.arm32 {
                let reg = find_str_reg(&def.arm32, a.watch_param)
                    .ok_or_else(|| err(format!("syscall '{sname}' arm32: no str param")))?;
                let fl_reg = match a.fl_param {
                    Some(p) => find_int_reg(&def.arm32, p).ok_or_else(|| {
                        err(format!("syscall '{sname}' arm32: no int param '{p}'"))
                    })?,
                    None => 0,
                };
                args_32.push((
                    nr32,
                    SyscallArgInfo {
                        str_reg_idx: reg,
                        flags: a.flags,
                        fl_reg_idx: fl_reg,
                        fl_mask: a.fl_mask,
                    },
                ));
            }
        }

        let mut watch_basenames = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        if let Some(watch) = &self.watch {
            for b in &watch.basenames {
                let n = b.len();
                if n == 0 || n >= WATCH_BASE_MAX {
                    return Err(err(format!(
                        "[watch]: basename '{b}' 长度须在 1..{} 字节",
                        WATCH_BASE_MAX - 1
                    )));
                }
                if !seen.insert(b.as_str()) {
                    continue;
                }
                watch_basenames.push(b.clone());
            }
        }

        args_64.sort_by_key(|(nr, _)| *nr);
        args_32.sort_by_key(|(nr, _)| *nr);

        Ok(ValidatedConfig {
            syscall_args_64: args_64,
            syscall_args_32: args_32,
            watch_basenames,
        })
    }
}

#[cfg(test)]
mod shipped_config_tests {
    use super::Config;
    use crate::types::SYSCALL_FLAG_WATCH;
    use std::path::Path;
    #[test]
    fn shipped_hunt_config_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../template/config.toml");
        let cfg = Config::load(&path).expect("load shipped config");
        let v = cfg.validate().expect("validate shipped config");

        let openat = v
            .syscall_args_64
            .iter()
            .find(|(nr, _)| *nr == 56)
            .expect("openat arm64 entry");
        assert_ne!(openat.1.flags & SYSCALL_FLAG_WATCH, 0);
        assert_eq!(openat.1.fl_reg_idx, 2);
        assert_eq!(openat.1.fl_mask, 0x40);
        assert_eq!(openat.1.str_reg_idx, 1);

        let renameat = v
            .syscall_args_64
            .iter()
            .find(|(nr, _)| *nr == 38)
            .expect("renameat arm64 entry");
        assert_ne!(renameat.1.flags & SYSCALL_FLAG_WATCH, 0);
        assert_eq!(renameat.1.fl_mask, 0);
        assert_eq!(renameat.1.str_reg_idx, 3);

        assert!(!v.syscall_args_64.iter().any(|(nr, _)| *nr == 8));
        let creat = v
            .syscall_args_32
            .iter()
            .find(|(nr, _)| *nr == 8)
            .expect("creat arm32 entry");
        assert_ne!(creat.1.flags & SYSCALL_FLAG_WATCH, 0);
        assert_eq!(creat.1.str_reg_idx, 0);

        let openat32 = v
            .syscall_args_32
            .iter()
            .find(|(nr, _)| *nr == 322)
            .expect("openat arm32 entry");
        assert_eq!(openat32.1.str_reg_idx, 1);
        assert_eq!(openat32.1.fl_reg_idx, 2);
        assert_eq!(openat32.1.fl_mask, 0x40);

        assert!(v.watch_basenames.is_empty());
    }

    #[test]
    fn mask_without_flag_param_rejected() {
        let toml = r#"
    [[syscall]]
    name = "openat"
    nr = { arm64 = 56 }
    arm64 = [ { reg = 1, type = "str", name = "path" } ]

    [[syscall_groups]]
    name = "create"
    syscalls = ["openat"]
    watch_flag_mask = 0x40

    [watch]
    basenames = ["a.jpg"]
    groups = ["create"]
    "#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn arm32_only_syscall_accepted() {
        let toml = r#"
    [[syscall]]
    name = "creat"
    nr = { arm32 = 8 }
    arm32 = [ { reg = 0, type = "str", name = "path" } ]

    [[syscall_groups]]
    name = "create_any"
    syscalls = ["creat"]

    [watch]
    basenames = ["a.jpg"]
    groups = ["create_any"]
    "#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        let v = cfg.validate().expect("validate");
        assert!(v.syscall_args_64.is_empty());
        assert_eq!(v.syscall_args_32.len(), 1);
        assert_eq!(v.syscall_args_32[0].0, 8);
    }

    #[test]
    fn watch_param_conflict_rejected() {
        let toml = r#"
    [[syscall]]
    name = "renameat"
    nr = { arm64 = 38 }
    arm64 = [
        { reg = 1, type = "str", name = "old" },
        { reg = 3, type = "str", name = "new" },
    ]

    [[syscall_groups]]
    name = "g1"
    syscalls = ["renameat"]
    watch_param = "old"

    [[syscall_groups]]
    name = "g2"
    syscalls = ["renameat"]
    watch_param = "new"

    [watch]
    basenames = ["a.jpg"]
    groups = ["g1", "g2"]
    "#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn too_long_basename_rejected() {
        let toml = format!(
            r#"
    [[syscall]]
    name = "creat"
    nr = {{ arm32 = 8 }}
    arm32 = [ {{ reg = 0, type = "str", name = "path" }} ]

    [[syscall_groups]]
    name = "g"
    syscalls = ["creat"]

    [watch]
    basenames = ["{}"]
    groups = ["g"]
    "#,
            "x".repeat(64)
        );
        let cfg: Config = toml::from_str(&toml).expect("parse");
        assert!(cfg.validate().is_err());
    }
}
