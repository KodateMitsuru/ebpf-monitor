#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

# shellcheck disable=SC2034  # consumed by the KSU installer environment
SKIPUNZIP=1

if [ "$KSU" != "true" ]; then
    abort "! This module requires KernelSU"
fi

if [ "$ARCH" != "arm64" ]; then
    abort "! This module only supports arm64"
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    abort "! Kernel BTF missing (/sys/kernel/btf/vmlinux); eBPF programs cannot be loaded"
fi

ui_print "- Installing eBPF File Monitor"

unzip -o "$ZIPFILE" -d "$MODPATH" >/dev/null 2>&1
if [ ! -f "$MODPATH/ebpf-monitor" ]; then
    abort "! ebpf-monitor binary missing from zip"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/ebpf-monitor" 0 0 0755
if [ -f "$MODPATH/ebpf-monitor-ctl" ]; then set_perm "$MODPATH/ebpf-monitor-ctl" 0 0 0755; fi
for f in customize.sh service.sh uninstall.sh action.sh; do
    set_perm "$MODPATH/$f" 0 0 0755
done

ui_print "- Kernel: $(uname -r)"
ui_print "- Load self-test"
if ! out=$("$MODPATH/ebpf-monitor" --loadtest 2>&1); then
    ui_print "! $out"
    abort "! eBPF load test failed; this module does not work on this kernel"
fi
ui_print "- $out"

ui_print "- Config: ksud module config (persist, per https://kernelsu.org/zh_CN/guide/module-config.html)"
ui_print "- Events: daemon SQLite /data/adb/ebpf-monitor/events.db; frontend OPFS via ctl.sock get-db (binary, spawn chunked)"
ui_print "- Control: ebpf-monitor (daemon, always-on) + ebpf-monitor-ctl (spawn, per-invocation, no open listener)"
ui_print "- Events: /data/adb/ebpf-monitor/events.db (sqlite, survives updates)"
ui_print "- Reboot to start the daemon; logs: adb logcat -s ebpf-monitor"
