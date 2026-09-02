#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

MODDIR="${MODPATH:-$(pwd)}"
BIN_CTL="$MODDIR/ebpf-monitor-ctl"

echo "== eBPF File Monitor =="
grep -E '^(name|version)=' "$MODDIR/module.prop"

echo ""
echo "== daemon =="
if out=$("$BIN_CTL" status 2>/dev/null); then
    echo "$out"
else
    echo "not running (takes effect after reboot)"
fi

echo ""
echo "== recent events (last 20) =="
"$BIN_CTL" events limit 20 2>/dev/null

echo ""
echo "logs:    adb logcat -s ebpf-monitor"
echo "events:  /data/adb/ebpf-monitor/events.db"
