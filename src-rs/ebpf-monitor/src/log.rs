// SPDX-License-Identifier: GPL-3.0-or-later
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

static VERBOSITY: AtomicU8 = AtomicU8::new(1);
const TAG: &str = "ebpf-monitor";
const ANDROID_LOG_INFO: i32 = 6;
const ANDROID_LOG_ERROR: i32 = 7;

type LogWriteFn =
    unsafe extern "C" fn(i32, *const libc::c_char, *const libc::c_char) -> libc::c_int;

static ANDROID_LOG: OnceLock<Option<LogWriteFn>> = OnceLock::new();

fn android_log() -> Option<LogWriteFn> {
    *ANDROID_LOG.get_or_init(|| unsafe {
        let handle = libc::dlopen(c"liblog.so".as_ptr(), libc::RTLD_NOW);
        if handle.is_null() {
            return None;
        }
        let sym = libc::dlsym(handle, c"__android_log_write".as_ptr());
        if sym.is_null() {
            return None;
        }
        Some(std::mem::transmute::<*mut libc::c_void, LogWriteFn>(sym))
    })
}

pub fn init(verbosity: u8) {
    VERBOSITY.store(verbosity, Ordering::Relaxed);
}

pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

pub fn emit_info(msg: &str) {
    if verbosity() < 1 {
        return;
    }
    emit(ANDROID_LOG_INFO, msg, true);
}

pub fn emit_error(msg: &str) {
    emit(ANDROID_LOG_ERROR, msg, false);
}

fn emit(prio: i32, msg: &str, to_stdout: bool) {
    match android_log() {
        Some(f) => unsafe {
            let tag = std::ffi::CString::new(TAG).unwrap();
            if let Ok(m) = std::ffi::CString::new(msg) {
                f(prio, tag.as_ptr(), m.as_ptr());
            }
        },
        None => {
            if to_stdout {
                println!("{}", msg);
            } else {
                eprintln!("{}", msg);
            }
        }
    }
}

macro_rules! info {
    ($($arg:tt)*) => { $crate::log::emit_info(&format!($($arg)*)) };
}
pub(crate) use info;

macro_rules! error {
    ($($arg:tt)*) => { $crate::log::emit_error(&format!($($arg)*)) };
}
pub(crate) use error;
