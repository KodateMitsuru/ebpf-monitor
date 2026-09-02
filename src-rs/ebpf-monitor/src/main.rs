// SPDX-License-Identifier: GPL-3.0-or-later
mod bpf_loader;
mod catalog;
mod btf;
mod cli;
mod config;
mod event_handler;
mod events;
mod ipc;
mod log;

use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use aya::programs::RawTracePoint;
use aya::{Btf, EbpfLoader};

use config::Config;

use bpf_loader::Maps;


static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_sigint(_: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

// kernel object compiled by build.rs (aya-build) into OUT_DIR.
// include_bytes_aligned: the loader zero-copy casts the bytes to parse BTF.
const BPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-monitor"));

fn main() -> anyhow::Result<()> {
    let args = cli::parse();
    if args.selftest {
        return selftest();
    }
    if args.loadtest {
        return loadtest();
    }
    serve(args)
}

fn selftest() -> anyhow::Result<()> {
    use std::io::{BufRead as _, Write as _};

    anyhow::ensure!(!BPF_OBJ.is_empty(), "内嵌 BPF 对象为空");

    let names = parse_elf_section_names(BPF_OBJ)?;
    for want in ["raw_tp/sys_enter", "raw_tp/sys_exit", "maps"] {
        anyhow::ensure!(
            names.iter().any(|n| n == want),
            "BPF 对象缺少段: {want}（实际段: {names:?}）"
        );
    }
    println!(
        "selftest: BPF 对象 OK（{} 段，含 raw_tp/sys_enter、sys_exit、maps）",
        names.len()
    );

    let dir = std::env::temp_dir().join(format!("ebpf-monitor-selftest-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, "version = 1\n")?;
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);
    let ipc = ipc::Ipc::new(dir.clone(), tx);
    let listener = ipc.bind()?;
    let handle = std::thread::spawn(move || ipc.serve(listener));

    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut stream = std::os::unix::net::UnixStream::connect(dir.join("ctl.sock"))?;
    stream.write_all(b"{\"cmd\":\"ping\"}\n")?;
    stream.flush()?;
    let mut line = String::new();
    {
        let mut reader = std::io::BufReader::new(&mut stream);
        reader.read_line(&mut line)?;
    }
    anyhow::ensure!(
        line.contains("\"ok\"") && line.contains("\"pong\""),
        "IPC ping 往返失败: {line}"
    );
    println!("selftest: IPC socket OK（ping→pong）");

    std::mem::drop(stream);
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&dir);
    println!("selftest: ALL OK");
    Ok(())
}

fn parse_elf_section_names(obj: &[u8]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(obj.len() > 64 && &obj[..4] == b"\x7fELF", "不是 ELF 对象");
    anyhow::ensure!(obj[4] == 2, "仅支持 ELF64");
    let rd16 =
        |o: usize| -> usize { u16::from_le_bytes(obj[o..o + 2].try_into().unwrap()) as usize };
    let rd32 =
        |o: usize| -> usize { u32::from_le_bytes(obj[o..o + 4].try_into().unwrap()) as usize };
    let rd64 = |o: usize| -> u64 { u64::from_le_bytes(obj[o..o + 8].try_into().unwrap()) };
    let shoff = rd64(0x28) as usize;
    let shentsize = rd16(0x3a);
    let shnum = rd16(0x3c);
    let shstrndx = rd16(0x3e);
    let shstr_hdr = shoff + shstrndx * shentsize;
    let shstr_off = rd64(shstr_hdr + 0x18) as usize;
    let mut out = Vec::new();
    for i in 0..shnum {
        let h = shoff + i * shentsize;
        let nameoff = rd32(h) as usize;
        let end = obj[shstr_off + nameoff..]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(0);
        let name = String::from_utf8_lossy(&obj[shstr_off + nameoff..shstr_off + nameoff + end])
            .into_owned();
        if !name.is_empty() {
            out.push(name);
        }
    }
    Ok(out)
}

fn resolve_persist_dir(config_path: Option<&Path>) -> PathBuf {
    if let Ok(dir) = std::env::var("EBPF_MONITOR_DIR") {
        let p = PathBuf::from(dir);
        if std::fs::create_dir_all(&p).is_ok() {
            return p;
        }
    }
    let device = PathBuf::from("/data/adb/ebpf-monitor");
    if std::fs::create_dir_all(&device).is_ok() {
        return device;
    }
    let fallback = config_path
        .and_then(|p| p.parent().map(|d| d.join(".ebpf-monitor")))
        .unwrap_or_else(|| PathBuf::from(".ebpf-monitor"));
    let _ = std::fs::create_dir_all(&fallback);
    fallback
}

fn load_bpf() -> anyhow::Result<(aya::Ebpf, Maps)> {
    let btf = Btf::from_sys_fs().map_err(|e| anyhow::anyhow!("BTF load failed (need /sys/kernel/btf/vmlinux, kernel ≥5.10): {e}"))?;
    let mut bpf = EbpfLoader::new().btf(Some(&btf)).load(BPF_OBJ)?;
    let mut maps = Maps::take(&mut bpf).map_err(|e| anyhow::anyhow!(e))?;
    // KMI 6.1 aarch64: task_struct.thread_info.flags at 0, TIF_32BIT=22 – static is correct.
    bpf_loader::apply_kernel_layout(&mut maps, btf::KernelLayout::ARM64_STATIC).map_err(|e| anyhow::anyhow!(e))?;

    for (prog_name, tp_name) in [("on_enter", "sys_enter"), ("on_exit", "sys_exit")] {
        let program: &mut RawTracePoint = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("bpf program '{prog_name}' missing in object"))?
            .try_into()?;
        program.load()?;
        program.attach(tp_name)?;
    }

    maps.pid_wl.insert(&std::process::id(), &1u8, 0)?;
    Ok((bpf, maps))
}
// The module installer runs this as a compatibility gate: maps get created,
// both raw tracepoints load and attach, then everything drops immediately.
// Needs root; non-zero exit means this kernel cannot host the module.
fn loadtest() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }
    let (bpf, maps) = load_bpf()?;
    drop(maps);
    drop(bpf);
    println!("loadtest OK (raw_tracepoint + BTF CO-RE)");
    Ok(())
}

fn serve(args: cli::CliArgs) -> anyhow::Result<()> {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
    }

    let rlim = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
            eprintln!("warning: failed to set RLIMIT_MEMLOCK");
        }
    }

    log::init(args.verbosity);

    let persist = resolve_persist_dir(None);
    events::init(&persist);

    let (_bpf, mut maps) = load_bpf()?;

    let config = Config::load();
    let mut nr_names: HashMap<u32, String> = HashMap::new();
    for s in catalog::syscalls() {
        if let Some(nr) = s.nr.arm64 {
            nr_names.insert(nr, s.name.clone());
        }
        if let Some(nr32) = s.nr.arm32 {
            nr_names.insert(nr32, s.name.clone());
        }
    }
    let uid_names = load_uid_names();

    let validated = config.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    bpf_loader::load_syscall_args(&mut maps, &validated).map_err(|e| anyhow::anyhow!("{e}"))?;
    bpf_loader::load_watch_rules(&mut maps, &validated).map_err(|e| anyhow::anyhow!("{e}"))?;
    bpf_loader::load_whitelist(&mut maps, &config).map_err(|e| anyhow::anyhow!("{e}"))?;

    let (tx, rx) = std::sync::mpsc::sync_channel::<ipc::Req>(4);
    let ipc_srv = ipc::Ipc::new(persist.clone(), tx);
    match ipc_srv.bind() {
        Ok(listener) => ipc_srv.serve(listener),
        Err(e) => {
            log::error!("IPC disabled (bind ctl.sock): {}", e);
            drop(ipc_srv);
        }
    }

    log::info!(
        "Monitoring file syscalls (persist {}, events seq {})",
        persist.display(),
        events::newest_seq()
    );

    let ring_fd = maps.events.as_fd().as_raw_fd();

    while RUNNING.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd: ring_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 100) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) && RUNNING.load(Ordering::Relaxed) {
                log::error!("poll error: {err}");
                break;
            }
        }

        loop {
            let item = match maps.events.next() {
                Some(item) => item,
                None => break,
            };
            event_handler::handle(&item, &nr_names, &uid_names);
        }

        let mut apply = || -> Result<(), String> {
            let new_cfg = Config::load();
            new_cfg.validate().map_err(|e| format!("validate: {e}"))?;
            bpf_loader::reload(&mut maps, &new_cfg)?;
            log::info!("config reloaded via KSU");
            Ok(())
        };
        ipc::drain_reload(&rx, &mut apply);
    }

    log::info!("Exiting.");
    drop(maps);
    drop(_bpf);
    Ok(())
}

fn load_uid_names() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/data/system/packages.list") {
        for line in content.lines() {
            let mut it = line.split_whitespace();
            if let (Some(pkg), Some(uid)) = (it.next(), it.next()) {
                if let Ok(uid) = uid.parse::<u32>() {
                    map.insert(uid, pkg.to_string());
                }
            }
        }
    }
    map
}
