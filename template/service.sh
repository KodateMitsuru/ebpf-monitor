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

    [ -f "$PERSIST/config.toml" ] || cp "$MODDIR/config.toml" "$PERSIST/config.toml"

    "$MODDIR/ebpf-monitor" -c "$PERSIST/config.toml" >/dev/null 2>&1 &
) &
