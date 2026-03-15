use crate::{
    apply_provider_heartbeat, dashboard_snapshot, ingest_behavioral_event, BehavioralEvent,
    ComponentState, DashboardSnapshot, DecisionOutcome, EscalationVector, ProviderCapability,
    ProviderDomain, ProviderHeartbeat, Reputation, SelfProtectionTechnique, SignatureState,
    ThreadOrigin,
};
use anyhow::{Context, Result};
use procfs::process::{all_processes, Process};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProviderScanReport {
    pub providers: Vec<ProviderHeartbeat>,
    pub events_ingested: usize,
    pub decisions: Vec<DecisionOutcome>,
    pub snapshot: DashboardSnapshot,
}

#[derive(Debug, Clone)]
struct SocketEntry {
    remote_address: String,
    remote_port: u16,
}

pub fn run_host_scan(limit: usize) -> Result<LinuxProviderScanReport> {
    let providers = provider_heartbeats();
    for heartbeat in providers.iter().cloned() {
        let _ = apply_provider_heartbeat(heartbeat)?;
    }

    let socket_table = load_socket_table().unwrap_or_default();
    let mut decisions = Vec::new();
    let mut events_ingested = 0usize;

    for process_result in all_processes().context("failed to iterate /proc")? {
        let process = match process_result {
            Ok(process) => process,
            Err(_) => continue,
        };

        if decisions.len() >= limit {
            break;
        }

        let process_events = collect_process_events(&process, &socket_table);
        for event in process_events {
            let outcome = ingest_behavioral_event(event)?;
            events_ingested += 1;
            if !matches!(outcome.action, crate::DecisionAction::Observe) {
                decisions.push(outcome);
                if decisions.len() >= limit {
                    break;
                }
            }
        }
    }

    Ok(LinuxProviderScanReport {
        providers,
        events_ingested,
        decisions,
        snapshot: dashboard_snapshot(),
    })
}

fn provider_heartbeats() -> Vec<ProviderHeartbeat> {
    vec![
        ProviderHeartbeat {
            id: "linux.file_gate".to_string(),
            label: "Linux File Gate".to_string(),
            domain: ProviderDomain::LinuxKernel,
            capabilities: vec![ProviderCapability::FileInterception],
            state: ComponentState::Degraded,
            detail: "User-space /proc collector online. Fanotify or LSM adapter not attached yet."
                .to_string(),
        },
        ProviderHeartbeat {
            id: "linux.ebpf_guard".to_string(),
            label: "Linux eBPF Guard".to_string(),
            domain: ProviderDomain::LinuxKernel,
            capabilities: vec![
                ProviderCapability::ThreadOriginValidation,
                ProviderCapability::SelfProtection,
            ],
            state: ComponentState::Degraded,
            detail: "Process, memory map, and ptrace heuristics are being collected from /proc."
                .to_string(),
        },
        ProviderHeartbeat {
            id: "linux.netfilter".to_string(),
            label: "Linux Netfilter Guard".to_string(),
            domain: ProviderDomain::LinuxKernel,
            capabilities: vec![ProviderCapability::NetworkInterception],
            state: ComponentState::Degraded,
            detail: "Socket destination heuristics are being collected from /proc/net/tcp*."
                .to_string(),
        },
    ]
}

fn collect_process_events(
    process: &Process,
    socket_table: &HashMap<u64, SocketEntry>,
) -> Vec<BehavioralEvent> {
    let pid = process.pid as u32;
    let stat = match process.stat() {
        Ok(stat) => stat,
        Err(_) => return Vec::new(),
    };

    let process_name = stat.comm.clone();
    let exe = process.exe().ok();
    let exe_path = exe
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    let parent_process = parent_name(stat.ppid).ok().flatten();

    let mut events = Vec::new();

    if is_user_writable_path(&exe_path) || looks_suspicious_name(&process_name) {
        events.push(BehavioralEvent::ExecutionStart {
            provider_id: "linux.file_gate".to_string(),
            process_id: pid,
            process_name: process_name.clone(),
            image_path: exe_path.clone(),
            parent_process: parent_process.clone(),
            launched_from_user_space: is_user_writable_path(&exe_path),
            signature_state: classify_linux_signature(&exe_path),
            requested_persistence: indicates_persistence(&exe_path),
        });
    }

    if let Some(origin) = suspicious_thread_origin(pid) {
        events.push(BehavioralEvent::ThreadInspection {
            provider_id: "linux.ebpf_guard".to_string(),
            process_id: pid,
            process_name: process_name.clone(),
            target_process: process_name.clone(),
            target_critical: is_critical_process(&process_name),
            cross_process: false,
            origin,
        });
    }

    if let Some(module_name) = suspicious_module(pid) {
        events.push(BehavioralEvent::ModuleIntegrity {
            provider_id: "linux.ebpf_guard".to_string(),
            process_id: pid,
            process_name: process_name.clone(),
            module_name,
            kernel_surface: false,
            unsigned: true,
            patched: false,
        });
    }

    if let Some(target) = ptrace_target(pid) {
        events.push(BehavioralEvent::SelfProtectionEvent {
            provider_id: "linux.ebpf_guard".to_string(),
            process_id: pid,
            process_name: process_name.clone(),
            target,
            technique: SelfProtectionTechnique::Ptrace,
        });
    }

    if let Some(vector_target) = privilege_escalation_target(&exe_path, &process_name) {
        events.push(BehavioralEvent::PrivilegeEscalation {
            provider_id: "linux.file_gate".to_string(),
            process_id: pid,
            process_name: process_name.clone(),
            target: vector_target,
            vector: EscalationVector::Setuid,
            tcc_bypass_attempt: false,
        });
    }

    for socket in process_sockets(pid, socket_table) {
        events.push(BehavioralEvent::NetworkConnection {
            provider_id: "linux.netfilter".to_string(),
            process_id: pid,
            process_name: process_name.clone(),
            remote_address: socket.remote_address.clone(),
            remote_port: socket.remote_port,
            encrypted: socket.remote_port == 443 || socket.remote_port == 8443,
            reputation: classify_reputation(&socket.remote_address, socket.remote_port),
            beacon_interval_seconds: None,
        });
    }

    events
}

fn parent_name(ppid: i32) -> Result<Option<String>> {
    if ppid <= 0 {
        return Ok(None);
    }
    let parent = Process::new(ppid)?;
    Ok(parent.stat().ok().map(|stat| stat.comm))
}

fn is_user_writable_path(path: &str) -> bool {
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn indicates_persistence(path: &str) -> bool {
    path.contains(".config/autostart")
        || path.contains("/systemd/user/")
        || path.contains("/etc/systemd/")
        || path.contains("/cron.")
}

fn looks_suspicious_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["inject", "loader", "miner", "crypt", "payload", "dropper"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn is_critical_process(name: &str) -> bool {
    matches!(
        name,
        "systemd" | "init" | "sshd" | "dbus-daemon" | "launchd" | "kernel_task"
    )
}

fn classify_linux_signature(path: &str) -> SignatureState {
    if path.starts_with("/usr/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/lib/")
        || path.starts_with("/snap/")
    {
        SignatureState::Trusted
    } else {
        SignatureState::Unsigned
    }
}

fn suspicious_thread_origin(pid: u32) -> Option<ThreadOrigin> {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = fs::read_to_string(maps_path).ok()?;

    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let _range = parts.next();
        let perms = parts.next().unwrap_or("");
        let _offset = parts.next();
        let _dev = parts.next();
        let _inode = parts.next();
        let pathname = parts.next().unwrap_or("");

        if !perms.contains('x') {
            continue;
        }

        if pathname.starts_with("memfd:") {
            return Some(ThreadOrigin::Jit);
        }

        if pathname.is_empty() || pathname == "[anon]" {
            return Some(ThreadOrigin::Heap);
        }

        if pathname.starts_with("/dev/shm/") || pathname.starts_with("/tmp/") {
            return Some(ThreadOrigin::Unknown);
        }
    }

    None
}

fn suspicious_module(pid: u32) -> Option<String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = fs::read_to_string(maps_path).ok()?;

    for line in maps.lines() {
        if line.contains(" (deleted)") {
            return line.split_whitespace().last().map(|s| s.to_string());
        }
    }

    None
}

fn ptrace_target(pid: u32) -> Option<String> {
    let status_path = format!("/proc/{}/status", pid);
    let status = fs::read_to_string(status_path).ok()?;
    let tracer = status
        .lines()
        .find(|line| line.starts_with("TracerPid:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<u32>()
        .ok()?;

    if tracer == 0 {
        return None;
    }

    Some(format!("traced by pid {}", tracer))
}

fn privilege_escalation_target(exe_path: &str, process_name: &str) -> Option<String> {
    let metadata = fs::metadata(exe_path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o4000 != 0 {
            return Some(format!("setuid path {}", process_name));
        }
    }
    None
}

fn process_sockets(pid: u32, socket_table: &HashMap<u64, SocketEntry>) -> Vec<SocketEntry> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match fs::read_dir(fd_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut inodes = HashSet::new();
    for entry in entries.flatten() {
        if let Ok(target) = fs::read_link(entry.path()) {
            if let Some(inode) = parse_socket_inode(&target) {
                inodes.insert(inode);
            }
        }
    }

    inodes
        .into_iter()
        .filter_map(|inode| socket_table.get(&inode).cloned())
        .filter(|socket| !is_loopback(&socket.remote_address))
        .collect()
}

fn parse_socket_inode(path: &Path) -> Option<u64> {
    let raw = path.to_string_lossy();
    let prefix = "socket:[";
    let suffix = "]";
    if raw.starts_with(prefix) && raw.ends_with(suffix) {
        return raw[prefix.len()..raw.len() - suffix.len()].parse().ok();
    }
    None
}

fn load_socket_table() -> Result<HashMap<u64, SocketEntry>> {
    let mut sockets = HashMap::new();
    parse_proc_net("/proc/net/tcp", false, &mut sockets)?;
    parse_proc_net("/proc/net/tcp6", true, &mut sockets)?;
    Ok(sockets)
}

fn parse_proc_net(path: &str, is_v6: bool, sockets: &mut HashMap<u64, SocketEntry>) -> Result<()> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return Ok(()),
    };

    for line in raw.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 10 {
            continue;
        }

        let remote = columns[2];
        let inode = match columns[9].parse::<u64>() {
            Ok(inode) => inode,
            Err(_) => continue,
        };

        if let Some((remote_address, remote_port)) = decode_socket_address(remote, is_v6) {
            sockets.insert(
                inode,
                SocketEntry {
                    remote_address,
                    remote_port,
                },
            );
        }
    }

    Ok(())
}

fn decode_socket_address(raw: &str, is_v6: bool) -> Option<(String, u16)> {
    let (host_hex, port_hex) = raw.split_once(':')?;
    let remote_port = u16::from_str_radix(port_hex, 16).ok()?;

    if is_v6 {
        if host_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, chunk) in host_hex.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).ok()?;
            bytes[index] = u8::from_str_radix(hex, 16).ok()?;
        }
        bytes.reverse();
        return Some((Ipv6Addr::from(bytes).to_string(), remote_port));
    }

    if host_hex.len() != 8 {
        return None;
    }

    let mut bytes = [0u8; 4];
    for (index, chunk) in host_hex.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        bytes[index] = u8::from_str_radix(hex, 16).ok()?;
    }
    bytes.reverse();

    Some((Ipv4Addr::from(bytes).to_string(), remote_port))
}

fn is_loopback(remote_address: &str) -> bool {
    remote_address == "0.0.0.0"
        || remote_address == "::"
        || remote_address == "127.0.0.1"
        || remote_address == "::1"
}

fn classify_reputation(remote_address: &str, remote_port: u16) -> Reputation {
    if is_loopback(remote_address) {
        Reputation::Trusted
    } else if matches!(remote_port, 22 | 53 | 80 | 123 | 443) {
        Reputation::Unknown
    } else if matches!(remote_port, 4444 | 1337 | 31337 | 5555 | 6667) {
        Reputation::Suspicious
    } else {
        Reputation::Unknown
    }
}
