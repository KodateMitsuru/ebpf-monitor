#![no_std]

//! Shared ABI – 560 B FileEvent for zero-copy ringbuf.

pub const MAX_PATH_LEN: usize = 256;
pub const TASK_COMM_LEN: usize = 16;
pub const WATCH_BASE_MAX: usize = 64;

pub const SYSCALL_FLAG_PRINT: u32 = 1 << 1;
pub const SYSCALL_FLAG_WATCH: u32 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallArgInfo {
    pub str_reg_idx: u32,
    pub flags: u32,
    pub fl_reg_idx: u32,
    pub fl_mask: u32,
}

/// File operation derived from watch groups.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
    Create = 0, // inode_create / file_open O_CREAT
    Mkdir = 1,  // path_mkdir
    Rename = 2, // path_rename (new path)
    Unlink = 3, // path_unlink
    Unknown = 0xFF,
}

impl From<u32> for FileOp {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Create,
            1 => Self::Mkdir,
            2 => Self::Rename,
            3 => Self::Unlink,
            _ => Self::Unknown,
        }
    }
}

/// Ringbuf event carrying file lifecycle. `old_fname` is set only for rename.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub syscall_nr: u32, // FileOp discriminant
    pub ret: i64,
    pub watched: u8,
    pub _pad1: [u8; 3],
    pub sflags: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub fname: [u8; MAX_PATH_LEN],
    pub old_fname: [u8; MAX_PATH_LEN],
}

pub type PrintEvent = FileEvent;

impl Default for FileEvent {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl FileEvent {
    pub fn op(&self) -> FileOp {
        FileOp::from(self.syscall_nr)
    }
}

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl plain::Plain for SyscallArgInfo {}
    unsafe impl aya::Pod for SyscallArgInfo {}
    unsafe impl plain::Plain for FileEvent {}
    unsafe impl aya::Pod for FileEvent {}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abi_layout() {
        assert_eq!(core::mem::size_of::<FileEvent>(), 560);
    }
}
