// SPDX-License-Identifier: GPL-3.0-or-later
#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_user_str_bytes,
};
use aya_ebpf::helpers::generated::{bpf_get_current_comm, bpf_get_current_task};
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::RawTracePointContext;

use ebpf_monitor_common::{PrintEvent, SyscallArgInfo, MAX_PATH_LEN, TASK_COMM_LEN, WATCH_BASE_MAX, SYSCALL_FLAG_PRINT, SYSCALL_FLAG_WATCH};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PendingPrint {
    pub syscall_nr: u32,
    pub watched: u8,
    pub _pad1: [u8; 3],
    pub sflags: u32,
    pub fname_ptr: u64,
    pub old_fname_ptr: u64,
}



// arm64 defaults for the CONFIG map slots; the daemon overwrites them with
// values resolved from the running kernel's BTF before serving
const DEFAULT_TIF_32BIT: u64 = 1 << 22;
// insert value for PENDING (BPF code cannot call memset)
static ZERO_PP: PendingPrint = PendingPrint {
    syscall_nr: 0,
    watched: 0,
    _pad1: [0; 3],
    sflags: 0,
    fname_ptr: 0,
    old_fname_ptr: 0,
};

const SLOT_PATH: u32 = 0;
const SLOT_KEY: u32 = 1;

// bpf_get_current_task via generated helper (BPF_FUNC_get_current_task, no BTF)
// bpf_get_current_comm via helper bpf_get_current_comm (no task_struct BTF)


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
// [0] = byte offset of task_struct->thread_info.flags,
// [1] = _TIF_32BIT bit mask. Injected from vmlinux BTF by the daemon at load.
#[map]
static CONFIG: Array<u64> = Array::with_max_entries(2, 0);

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


#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn on_enter(ctx: RawTracePointContext) -> u32 {
    let _ = try_enter(&ctx);
    0
}

fn try_enter(ctx: &RawTracePointContext) -> Result<(), i64> {
    let regs = ctx.arg::<u64>(0);
    let id = ctx.arg::<u64>(1) as u32;

    let task = unsafe { bpf_get_current_task() } as *const u64;
    if task.is_null() {
        return Ok(());
    }
    // thread_info.flags read through its BTF-resolved offset (0 == the static
    // arm64 layout: thread_info first member, flags first field)
    let flags_off = CONFIG.get(0).map(|v| *v).unwrap_or(0)  as usize;
    let tflags = unsafe {
        bpf_probe_read_kernel::<u64>((task as *const u8).wrapping_add(flags_off) as *const u64)?
    };
    let is32 = tflags &  CONFIG.get(1).map(|v| *v).unwrap_or(DEFAULT_TIF_32BIT) != 0;

    let info_ref = if is32 {
        unsafe { ARGS32.get(&id) }
    } else {
        unsafe { ARGS64.get(&id) }
    };
    let Some(info) = info_ref else { return Ok(()) };
    let info = *info;


    let pid_tgid = bpf_get_current_pid_tgid();
    let uid = ( bpf_get_current_uid_gid()  & 0xFFFF_FFFF) as u32;
    if unsafe { PID_WL.get(&((pid_tgid >> 32) as u32)) }.is_some()
        || unsafe { UID_WL.get(&uid) }.is_some()
    {
        return Ok(());
    }

    let mut fname_ptr = unsafe {
        bpf_probe_read_kernel::<u64>((regs + info.str_reg_idx as u64 * 8) as *const u64)?
    };
    if fname_ptr == 0 {
        return Ok(());
    }
    let mut old_fname_ptr: u64 = 0;
    // rename family: capture both old and new paths for lifecycle chain
    let is_rename = id == 34 || id == 38 || id == 276;
    if is_rename {
        old_fname_ptr = fname_ptr;
        let new_ptr = unsafe {
            bpf_probe_read_kernel::<u64>((regs + (info.str_reg_idx as u64 + 2) * 8) as *const u64)?
        };
        if new_ptr != 0 {
            fname_ptr = new_ptr;
        }
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
            let mut hit = false;
            if let (Some(pathbuf), Some(keybuf)) = (RBUF.get_ptr_mut(SLOT_PATH), RBUF.get_ptr_mut(SLOT_KEY)) {
                if let Ok(path) = unsafe { bpf_probe_read_user_str_bytes(fname_ptr as *const u8, &mut (*pathbuf).b) } {
                    hit = unsafe { watch_hit(path.as_ptr(), path.len(), (*keybuf).b.as_mut_ptr()) };
                }
                if !hit && old_fname_ptr != 0 {
                    if let Ok(path) = unsafe { bpf_probe_read_user_str_bytes(old_fname_ptr as *const u8, &mut (*pathbuf).b) } {
                        hit = unsafe { watch_hit(path.as_ptr(), path.len(), (*keybuf).b.as_mut_ptr()) };
                    }
                }
            }
            watch_ok = hit;
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
    if let Some(pp) =  PENDING.get_ptr_mut(&pid_tgid)  {
        unsafe {
            (*pp).syscall_nr = id;
            (*pp).watched = watched;
            (*pp).sflags = sflags;
            (*pp).fname_ptr = fname_ptr;
            (*pp).old_fname_ptr = old_fname_ptr;
        }
    }
    Ok(())
}

unsafe fn watch_hit(path: *const u8, len: usize, key: *mut u8) -> bool {
    // walk from the path end so the loop bound is static for the verifier;
    // len is without NUL (bpf_probe_read_user_str_bytes returns &[u8] without terminator)
    let last = len as isize - 1;
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


#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn on_exit(ctx: RawTracePointContext) -> u32 {
    let _ = try_exit(&ctx);
    0
}

fn try_exit(ctx: &RawTracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid() ;
    let Some(pp_ref) = (unsafe { PENDING.get(&pid_tgid) }) else {
        return Ok(());
    };
    let syscall_nr = (*pp_ref).syscall_nr;
    let watched = (*pp_ref).watched;
    let sflags = (*pp_ref).sflags;
    let fname_ptr = (*pp_ref).fname_ptr;
    let old_fname_ptr = (*pp_ref).old_fname_ptr;

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
                core::ptr::addr_of_mut!((*p).comm) as *mut _,
                TASK_COMM_LEN as u32,
            );
            let _ = bpf_probe_read_user_str_bytes(fname_ptr as *const u8, &mut (*p).fname);
            if old_fname_ptr != 0 {
                let _ = bpf_probe_read_user_str_bytes(old_fname_ptr as *const u8, &mut (*p).old_fname);
            }
        }
        reservation.submit(0);
    }
    let _ = PENDING.remove(&pid_tgid);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(not(test))]
#[allow(dead_code)]
fn main() {}
