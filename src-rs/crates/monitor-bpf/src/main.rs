// SPDX-License-Identifier: GPL-3.0-or-later
//! Kernel side: raw_tracepoint syscall watcher driven by config maps.
#![no_std]
#![no_main]
#![allow(deprecated)]
#![allow(clippy::missing_safety_doc)]
#![allow(unused_unsafe)]

use aya_ebpf::cty::c_char;
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_user_str,
};
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{HashMap, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::RawTracePointContext;

mod types;

use types::{
    PendingPrint, PrintEvent, SyscallArgInfo, MAX_PATH_LEN, SYSCALL_FLAG_PRINT, SYSCALL_FLAG_WATCH,
    TASK_COMM_LEN, WATCH_BASE_MAX,
};

// thread_info.flags bit marking a 32-bit compat task (arm64 TIF_32BIT)
const _TIF_32BIT: u64 = 1 << 22;

// insert value for PENDING (BPF code cannot call memset)
static ZERO_PP: PendingPrint = PendingPrint {
    syscall_nr: 0,
    watched: 0,
    _pad1: [0; 3],
    sflags: 0,
    fname_ptr: 0,
};

const SLOT_PATH: u32 = 0;
const SLOT_KEY: u32 = 1;

unsafe extern "C" {
    fn bpf_get_current_task() -> isize;
    fn bpf_get_current_comm(buf: *mut c_char, size_of_buf: u32) -> i32;
}

// ---------------- maps ----------------

#[map]
static ARGS64: HashMap<u32, SyscallArgInfo> = HashMap::with_max_entries(32, 0);
#[map]
static ARGS32: HashMap<u32, SyscallArgInfo> = HashMap::with_max_entries(32, 0);
#[map]
static WATCH_RULES: HashMap<[u8; WATCH_BASE_MAX], u8> = HashMap::with_max_entries(64, 0);
#[map]
static PID_WL: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static UID_WL: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static PENDING: LruHashMap<u64, PendingPrint> = LruHashMap::with_max_entries(1024, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Scratch {
    pub b: [u8; MAX_PATH_LEN],
}

impl Default for Scratch {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[map]
static RBUF: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(2, 0);

// ---------------- sys_enter ----------------

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn on_enter(ctx: RawTracePointContext) -> u32 {
    let _ = try_enter(&ctx);
    0
}

fn try_enter(ctx: &RawTracePointContext) -> Result<(), i64> {
    let regs = ctx.arg::<u64>(0); // struct pt_regs *
    let id = ctx.arg::<u64>(1) as u32;

    let task = unsafe { bpf_get_current_task() } as *const u64;
    if task.is_null() {
        return Ok(());
    }
    // on arm64 thread_info is task_struct's first member and flags its first
    // field, so this word *is* thread_info.flags (no CO-RE used)
    let tflags = unsafe { bpf_probe_read_kernel::<u64>(task)? };
    let is32 = tflags & _TIF_32BIT != 0;

    let info_ref = if is32 {
        unsafe { ARGS32.get(&id) }
    } else {
        unsafe { ARGS64.get(&id) }
    };
    let Some(info) = info_ref else { return Ok(()) };
    let info = *info;

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid = (unsafe { bpf_get_current_uid_gid() } & 0xFFFF_FFFF) as u32;
    if unsafe { PID_WL.get(&((pid_tgid >> 32) as u32)) }.is_some()
        || unsafe { UID_WL.get(&uid) }.is_some()
    {
        return Ok(());
    }

    let fname_ptr = unsafe {
        bpf_probe_read_kernel::<u64>((regs + info.str_reg_idx as u64 * 8) as *const u64)?
    };
    if fname_ptr == 0 {
        return Ok(());
    }

    let mut watched = 0u8;
    let mut sflags = 0u32;
    let mut do_print = info.flags & SYSCALL_FLAG_PRINT != 0;

    if info.flags & SYSCALL_FLAG_WATCH != 0 {
        let mut watch_ok = true;
        if info.fl_mask != 0 {
            sflags = unsafe {
                bpf_probe_read_kernel::<u64>((regs + info.fl_reg_idx as u64 * 8) as *const u64)
            }
            .unwrap_or(0) as u32;
            watch_ok = sflags & info.fl_mask != 0;
        }
        if watch_ok {
            watch_ok = match (unsafe { RBUF.get_ptr_mut(SLOT_PATH) }, unsafe {
                RBUF.get_ptr_mut(SLOT_KEY)
            }) {
                (Some(pathbuf), Some(keybuf)) => {
                    match unsafe {
                        bpf_probe_read_user_str(fname_ptr as *const u8, &mut (*pathbuf).b)
                    } {
                        Ok(len) if len > 0 => unsafe {
                            watch_hit(
                                (*pathbuf).b.as_ptr(),
                                len as usize,
                                (*keybuf).b.as_mut_ptr(),
                            )
                        },
                        _ => false,
                    }
                }
                _ => false,
            };
        }
        if watch_ok {
            watched = 1;
            do_print = true;
        }
    }
    if !do_print {
        return Ok(());
    }

    let _ = PENDING.insert(&pid_tgid, &ZERO_PP, 0);
    if let Some(pp) = unsafe { PENDING.get_ptr_mut(&pid_tgid) } {
        unsafe {
            (*pp).syscall_nr = id;
            (*pp).watched = watched;
            (*pp).sflags = sflags;
            (*pp).fname_ptr = fname_ptr;
        }
    }
    Ok(())
}

unsafe fn watch_hit(path: *const u8, len: usize, key: *mut u8) -> bool {
    // walk from the path end so the loop bound is static for the verifier;
    // -2 skips the NUL terminator of the probe-read buffer
    let last = len as isize - 2;
    let mut d: usize = 0;
    let mut terminated = false;
    while d < WATCH_BASE_MAX {
        let mut b: u8 = 0;
        if !terminated {
            let idx = last - d as isize;
            if idx < 0 {
                terminated = true;
            } else {
                let c = unsafe { *path.add((idx as usize) & 0xFF) };
                if c == b'/' {
                    terminated = true;
                } else {
                    b = c;
                }
            }
        }
        unsafe { *key.add(WATCH_BASE_MAX - 1 - d) = b };
        d += 1;
    }
    if !terminated {
        return false;
    }
    let kref: &[u8; WATCH_BASE_MAX] = unsafe { &*(key as *const [u8; WATCH_BASE_MAX]) };
    unsafe { WATCH_RULES.get(kref) }.is_some()
}

// ---------------- sys_exit ----------------

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn on_exit(ctx: RawTracePointContext) -> u32 {
    let _ = try_exit(&ctx);
    0
}

fn try_exit(ctx: &RawTracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let Some(pp_ref) = (unsafe { PENDING.get(&pid_tgid) }) else {
        return Ok(());
    };
    let syscall_nr = (*pp_ref).syscall_nr;
    let watched = (*pp_ref).watched;
    let sflags = (*pp_ref).sflags;
    let fname_ptr = (*pp_ref).fname_ptr;

    let ret = ctx.arg::<i64>(1);
    if let Some(mut reservation) = EVENTS.reserve_bytes(core::mem::size_of::<PrintEvent>(), 0) {
        let p = reservation.as_mut_ptr() as *mut PrintEvent;
        unsafe {
            (*p).pid = (pid_tgid >> 32) as u32;
            (*p).tid = pid_tgid as u32;
            (*p).uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
            (*p).syscall_nr = syscall_nr;
            (*p).ret = ret;
            (*p).watched = watched;
            (*p).sflags = sflags;
            bpf_get_current_comm(
                core::ptr::addr_of_mut!((*p).comm) as *mut c_char,
                TASK_COMM_LEN as u32,
            );
            let _ = bpf_probe_read_user_str(fname_ptr as *const u8, &mut (*p).fname);
        }
        reservation.submit(0);
    }
    let _ = PENDING.remove(&pid_tgid);
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[allow(dead_code)]
fn main() {}
