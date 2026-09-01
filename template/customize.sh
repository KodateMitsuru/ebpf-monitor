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

ui_print "- Config & events: /data/adb/ebpf-monitor (survives module updates)"
ui_print "- Reboot to start the daemon; logs: adb logcat -s ebpf-monitor"
