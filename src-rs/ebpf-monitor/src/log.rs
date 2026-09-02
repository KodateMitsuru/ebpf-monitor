// SPDX-License-Identifier: GPL-3.0-or-later
use std::sync::atomic::{AtomicU8, Ordering};
use log::LevelFilter;

static VERBOSITY: AtomicU8 = AtomicU8::new(1);

pub fn init(verbosity: u8) {
    VERBOSITY.store(verbosity, Ordering::Relaxed);
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("ebpf-monitor")
                .with_max_level(level),
        );
    }
    #[cfg(not(target_os = "android"))]
    {
        // Host builds (`cargo check` / `cargo run` on linux) use env_logger
        let _ = env_logger::builder().filter_level(level).try_init();
        log::set_max_level(level);
    }
}

pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

macro_rules! info {
    ($($arg:tt)*) => { ::log::info!($($arg)*) };
}
pub(crate) use info;

macro_rules! error {
    ($($arg:tt)*) => { ::log::error!($($arg)*) };
}
pub(crate) use error;
