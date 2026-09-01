#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

pkill -f "ebpf-monitor -c" 2>/dev/null || true
rm -rf /data/adb/ebpf-monitor
