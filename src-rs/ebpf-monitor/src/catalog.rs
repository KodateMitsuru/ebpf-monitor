// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SyscallDef {
    pub name: String,
    pub nr: SyscallNr,
    #[serde(default)]
    pub arm64: Vec<ArgDef>,
    #[serde(default)]
    pub arm32: Vec<ArgDef>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SyscallNr {
    #[serde(default)]
    pub arm64: Option<u32>,
    #[serde(default)]
    pub arm32: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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

fn string_param(reg: u32, name: &str) -> ArgDef {
    ArgDef { reg, arg_type: ArgType::Str, name: name.to_string() }
}
fn int_param(reg: u32, name: &str) -> ArgDef {
    ArgDef { reg, arg_type: ArgType::Int, name: name.to_string() }
}

pub fn syscalls() -> Vec<SyscallDef> {
    vec![
        SyscallDef { name: "openat".into(), nr: SyscallNr { arm64: Some(56), arm32: Some(322) }, arm64: vec![string_param(1, "path"), int_param(2, "flags")], arm32: vec![string_param(1, "path"), int_param(2, "flags")] },
        SyscallDef { name: "openat2".into(), nr: SyscallNr { arm64: Some(437), arm32: None }, arm64: vec![string_param(1, "path")], arm32: vec![] },
        SyscallDef { name: "creat".into(), nr: SyscallNr { arm64: None, arm32: Some(8) }, arm64: vec![], arm32: vec![string_param(0, "path")] },
        SyscallDef { name: "mkdirat".into(), nr: SyscallNr { arm64: Some(34), arm32: Some(323) }, arm64: vec![string_param(1, "path")], arm32: vec![string_param(1, "path")] },
        SyscallDef { name: "mkdir".into(), nr: SyscallNr { arm64: None, arm32: Some(39) }, arm64: vec![], arm32: vec![string_param(0, "path")] },
        SyscallDef { name: "renameat".into(), nr: SyscallNr { arm64: Some(38), arm32: Some(329) }, arm64: vec![string_param(1, "old"), string_param(3, "new")], arm32: vec![string_param(1, "old"), string_param(3, "new")] },
        SyscallDef { name: "renameat2".into(), nr: SyscallNr { arm64: Some(276), arm32: Some(382) }, arm64: vec![string_param(1, "old"), string_param(3, "new")], arm32: vec![string_param(1, "old"), string_param(3, "new")] },
        SyscallDef { name: "rename".into(), nr: SyscallNr { arm64: None, arm32: Some(38) }, arm64: vec![], arm32: vec![string_param(0, "old"), string_param(1, "new")] },
        SyscallDef { name: "unlinkat".into(), nr: SyscallNr { arm64: Some(35), arm32: Some(328) }, arm64: vec![string_param(1, "path")], arm32: vec![string_param(1, "path")] },
        SyscallDef { name: "unlink".into(), nr: SyscallNr { arm64: None, arm32: Some(10) }, arm64: vec![], arm32: vec![string_param(0, "path")] },
    ]
}

pub fn syscall_groups() -> Vec<SyscallGroup> {
    vec![
        SyscallGroup { name: "create".into(), syscalls: vec!["openat".into()], watch_param: None, watch_flag_param: Some("flags".into()), watch_flag_mask: Some(0x40) },
        SyscallGroup { name: "create_any".into(), syscalls: vec!["openat2".into(), "creat".into(), "mkdirat".into(), "mkdir".into()], watch_param: None, watch_flag_param: None, watch_flag_mask: None },
        SyscallGroup { name: "rename_".into(), syscalls: vec!["renameat".into(), "renameat2".into(), "rename".into()], watch_param: Some("new".into()), watch_flag_param: None, watch_flag_mask: None },
        SyscallGroup { name: "open_".into(), syscalls: vec!["openat".into()], watch_param: None, watch_flag_param: None, watch_flag_mask: None },
        SyscallGroup { name: "delete".into(), syscalls: vec!["unlinkat".into(), "unlink".into()], watch_param: None, watch_flag_param: None, watch_flag_mask: None },
    ]
}

pub fn default_groups() -> Vec<String> {
    vec!["create".into(), "create_any".into(), "rename_".into(), "delete".into()]
}
