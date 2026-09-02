// SPDX-License-Identifier: GPL-3.0-or-later
//! KMI 6.1: thread_info.flags at 0, TIF_32BIT=22.

#[derive(Debug, Clone, Copy)]
pub struct KernelLayout {
    pub flags_off: u64,
    pub tif32_mask: u64,
}

impl KernelLayout {
    pub const ARM64_STATIC: Self = Self { flags_off: 0, tif32_mask: 1 << 22 };
}
