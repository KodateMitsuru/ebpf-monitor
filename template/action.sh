#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

MODDIR="${MODPATH:-$(pwd)}"
BIN="$MODDIR/ebpf-monitor"

echo "== eBPF File Monitor =="
grep -E '^(name|version)=' "$MODDIR/module.prop"

echo ""
echo "== daemon =="
if out=$("$BIN" ctl status 2>/dev/null); then
    echo "$out"
else
    echo "not running (takes effect after reboot)"
fi

echo ""
echo "== recent events (last 20) =="
"$BIN" ctl events limit=20 2>/dev/null

echo ""
echo "logs:    adb logcat -s ebpf-monitor"
echo "events:  /data/adb/ebpf-monitor/events.jsonl"
