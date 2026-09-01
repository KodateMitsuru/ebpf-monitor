// SPDX-License-Identifier: GPL-3.0-or-later

pub const MAX_PATH_LEN: usize = 256;
pub const TASK_COMM_LEN: usize = 16;
pub const WATCH_BASE_MAX: usize = 64;

// syscall_arg_info.flags
pub const SYSCALL_FLAG_PRINT: u32 = 1 << 1;
pub const SYSCALL_FLAG_WATCH: u32 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SyscallArgInfo {
    pub str_reg_idx: u32,
    pub flags: u32,
    pub fl_reg_idx: u32,
    pub fl_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PendingPrint {
    pub syscall_nr: u32,
    pub watched: u8,
    pub _pad1: [u8; 3],
    pub sflags: u32,
    pub fname_ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrintEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub syscall_nr: u32,
    pub ret: i64,
    pub watched: u8,
    pub _pad1: [u8; 3],
    pub sflags: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub fname: [u8; MAX_PATH_LEN],
}

macro_rules! impl_default_zeroed {
    ($t:ty) => {
        impl Default for $t {
            fn default() -> Self {
                unsafe { core::mem::zeroed() }
            }
        }
    };
}
impl_default_zeroed!(PrintEvent);
