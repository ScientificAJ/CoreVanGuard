use crate::{
    apply_provider_heartbeat, ingest_behavioral_event, BehavioralEvent, ComponentState,
    DashboardSnapshot, DecisionAction, DecisionOutcome, ProviderCapability, ProviderDomain,
    ProviderHeartbeat, SignatureState,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxGuardReport {
    pub guarded_paths: Vec<String>,
    pub events_observed: usize,
    pub denied_events: usize,
    pub decisions: Vec<DecisionOutcome>,
    pub snapshot: DashboardSnapshot,
}

#[cfg(target_os = "linux")]
pub fn run_fanotify_guard(paths: &[PathBuf], max_events: usize) -> Result<LinuxGuardReport> {
    if paths.is_empty() {
        bail!("at least one protected path is required");
    }

    let _ = apply_provider_heartbeat(ProviderHeartbeat {
        id: "linux.file_gate".to_string(),
        label: "Linux File Gate".to_string(),
        domain: ProviderDomain::LinuxKernel,
        capabilities: vec![ProviderCapability::FileInterception],
        state: ComponentState::Online,
        detail: "Fanotify permission guard attached to protected paths.".to_string(),
    })?;

    let fan_fd = fanotify_init()?;
    let mut denied_events = 0usize;
    let mut events_observed = 0usize;
    let mut decisions = Vec::new();

    for path in paths {
        fanotify_mark_path(fan_fd, path)?;
    }

    let mut buffer = vec![0u8; 16 * 1024];

    while max_events == 0 || events_observed < max_events {
        let read_len = unsafe { libc::read(fan_fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read_len < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            close_fd(fan_fd);
            return Err(error).context("failed reading fanotify events");
        }

        if read_len == 0 {
            continue;
        }

        let mut offset = 0usize;
        while offset + size_of::<libc::fanotify_event_metadata>() <= read_len as usize {
            let metadata =
                unsafe { *(buffer.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };

            if metadata.fd >= 0 {
                let path = fd_path(metadata.fd);
                let outcome = evaluate_permission_event(metadata.pid as u32, &path)?;
                let deny = outcome.action >= DecisionAction::BlockOperation;
                write_fanotify_response(fan_fd, metadata.fd, deny)?;
                unsafe { libc::close(metadata.fd) };

                if deny {
                    denied_events += 1;
                }
                events_observed += 1;
                decisions.push(outcome);

                if max_events > 0 && events_observed >= max_events {
                    break;
                }
            }

            if metadata.event_len == 0 {
                break;
            }
            offset += metadata.event_len as usize;
        }
    }

    close_fd(fan_fd);

    Ok(LinuxGuardReport {
        guarded_paths: paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        events_observed,
        denied_events,
        decisions,
        snapshot: crate::dashboard_snapshot(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn run_fanotify_guard(_paths: &[PathBuf], _max_events: usize) -> Result<LinuxGuardReport> {
    bail!("fanotify guard is only available on Linux")
}

#[cfg(target_os = "linux")]
fn fanotify_init() -> Result<RawFd> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            (libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT) as libc::c_uint,
            (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
        ) as libc::c_int
    };

    if fd < 0 {
        bail!("{}", std::io::Error::last_os_error());
    }

    Ok(fd)
}

#[cfg(target_os = "linux")]
fn fanotify_mark_path(fan_fd: RawFd, path: &Path) -> Result<()> {
    let path_cstr = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("protected path contains interior NUL: {}", path.display()))?;
    let mut flags = libc::FAN_MARK_ADD;
    if path.is_dir() {
        flags |= libc::FAN_MARK_ONLYDIR;
    }

    let mask = (libc::FAN_OPEN_PERM | libc::FAN_EVENT_ON_CHILD) as u64;
    let result = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd,
            flags,
            mask,
            libc::AT_FDCWD,
            path_cstr.as_ptr(),
        ) as libc::c_int
    };

    if result != 0 {
        bail!(
            "failed to mark {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn fd_path(fd: RawFd) -> String {
    fs::read_link(format!("/proc/self/fd/{}", fd))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

#[cfg(target_os = "linux")]
fn evaluate_permission_event(process_id: u32, path: &str) -> Result<DecisionOutcome> {
    let process_name =
        read_process_name(process_id).unwrap_or_else(|| format!("pid-{}", process_id));
    let exe_path = read_process_exe(process_id).unwrap_or_else(|| "<unknown>".to_string());

    let _ = ingest_behavioral_event(BehavioralEvent::ExecutionStart {
        provider_id: "linux.file_gate".to_string(),
        process_id,
        process_name: process_name.clone(),
        image_path: exe_path.clone(),
        parent_process: None,
        launched_from_user_space: is_user_writable_path(&exe_path),
        signature_state: classify_linux_signature(&exe_path),
        requested_persistence: indicates_persistence(&exe_path),
    })?;

    ingest_behavioral_event(BehavioralEvent::FileMutation {
        provider_id: "linux.file_gate".to_string(),
        process_id,
        process_name,
        path: path.to_string(),
        bytes_written: 4096,
        entropy: 0.0,
        protected_path: true,
        canary_file: is_canary_path(path),
    })
}

#[cfg(target_os = "linux")]
fn write_fanotify_response(fan_fd: RawFd, event_fd: RawFd, deny: bool) -> Result<()> {
    let response = libc::fanotify_response {
        fd: event_fd,
        response: if deny {
            libc::FAN_DENY
        } else {
            libc::FAN_ALLOW
        },
    };

    let result = unsafe {
        libc::write(
            fan_fd,
            (&response as *const libc::fanotify_response).cast(),
            size_of::<libc::fanotify_response>(),
        )
    };

    if result < 0 {
        bail!("{}", std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

#[cfg(target_os = "linux")]
fn read_process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|value| value.trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_process_exe(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|path| path.display().to_string())
}

#[cfg(target_os = "linux")]
fn is_user_writable_path(path: &str) -> bool {
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn indicates_persistence(path: &str) -> bool {
    [
        "/etc/systemd/",
        "/usr/lib/systemd/",
        "/etc/init.d/",
        "/etc/cron",
        ".config/autostart",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

#[cfg(target_os = "linux")]
fn classify_linux_signature(path: &str) -> SignatureState {
    if path.starts_with("/usr/") || path.starts_with("/bin/") || path.starts_with("/sbin/") {
        SignatureState::Trusted
    } else if path == "<unknown>" {
        SignatureState::Tampered
    } else {
        SignatureState::Unsigned
    }
}

#[cfg(target_os = "linux")]
fn is_canary_path(path: &str) -> bool {
    path.contains(".corevanguard-canary") || path.contains("CoreVanguardCanary")
}
