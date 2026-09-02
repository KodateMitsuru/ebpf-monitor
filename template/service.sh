#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

MODDIR=${0%/*}
PERSIST=/data/adb/ebpf-monitor

(
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 1
    done
    sleep 5

    mkdir -p "$PERSIST"
    chmod 700 "$PERSIST"

    out=$("$MODDIR/ebpf-monitor" --loadtest 2>&1)
    # If this boot's binary cannot load its own program, say so loudly in
    # logcat instead of dying silently.
    out=$("$MODDIR/ebpf-monitor" --loadtest 2>&1)
    rc=$?
    printf '%s\n' "$out" | while IFS= read -r l; do log -t ebpf-monitor "$l"; done
    if [ "$rc" -ne 0 ]; then
        log -t ebpf-monitor "loadtest failed; daemon not started"
        exit 1
    fi

    "$MODDIR/ebpf-monitor" &
) &
