use crate::{DecisionAction, DecisionOutcome};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementState {
    Applied,
    Skipped,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub process_id: u32,
    pub process_name: String,
    pub action: DecisionAction,
    pub state: EnforcementState,
    pub detail: String,
}

pub fn enforce_outcome(outcome: &DecisionOutcome) -> Result<EnforcementReport> {
    match outcome.action {
        DecisionAction::Observe | DecisionAction::Escalate => Ok(EnforcementReport {
            process_id: outcome.process_id,
            process_name: outcome.process_name.clone(),
            action: outcome.action,
            state: EnforcementState::Skipped,
            detail: "Decision was observational only. No native containment action was applied."
                .to_string(),
        }),
        DecisionAction::BlockOperation => Ok(EnforcementReport {
            process_id: outcome.process_id,
            process_name: outcome.process_name.clone(),
            action: outcome.action,
            state: EnforcementState::Unsupported,
            detail:
                "Block-operation enforcement requires provider-specific handle or file revocation."
                    .to_string(),
        }),
        DecisionAction::FreezeProcess | DecisionAction::EmergencyLockdown => {
            stop_process(outcome.process_id).with_context(|| {
                format!(
                    "failed to stop pid {} for action {:?}",
                    outcome.process_id, outcome.action
                )
            })?;

            Ok(EnforcementReport {
                process_id: outcome.process_id,
                process_name: outcome.process_name.clone(),
                action: outcome.action,
                state: EnforcementState::Applied,
                detail: format!(
                    "Native containment signal applied to pid {}.",
                    outcome.process_id
                ),
            })
        }
    }
}

pub fn resume_process(process_id: u32) -> Result<()> {
    continue_process(process_id).with_context(|| format!("failed to resume pid {}", process_id))?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_process(process_id: u32) -> Result<()> {
    let result = unsafe { libc::kill(process_id as i32, libc::SIGSTOP) };
    if result != 0 {
        bail!("{}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn continue_process(process_id: u32) -> Result<()> {
    let result = unsafe { libc::kill(process_id as i32, libc::SIGCONT) };
    if result != 0 {
        bail!("{}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn stop_process(_process_id: u32) -> Result<()> {
    bail!("Windows containment requires the kernel control port adapter.")
}

#[cfg(target_os = "windows")]
fn continue_process(_process_id: u32) -> Result<()> {
    bail!("Windows containment release requires the kernel control port adapter.")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn stop_process(_process_id: u32) -> Result<()> {
    bail!("Process containment is unsupported on this host OS.")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn continue_process(_process_id: u32) -> Result<()> {
    bail!("Process resume is unsupported on this host OS.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    fn process_state(pid: u32) -> String {
        let status = fs::read_to_string(format!("/proc/{}/status", pid)).unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix("State:\t"))
            .unwrap_or("")
            .to_string()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn freeze_process_applies_sigstop() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();

        let outcome = DecisionOutcome {
            process_id: pid,
            process_name: "sleep".to_string(),
            provider_id: "linux.ebpf_guard".to_string(),
            tier1_score: 10,
            tier2_score: 20,
            tier3_score: 40,
            total_score: 70,
            action: DecisionAction::FreezeProcess,
            reasons: vec!["test freeze".to_string()],
        };

        let report = enforce_outcome(&outcome).unwrap();
        assert_eq!(report.state, EnforcementState::Applied);

        thread::sleep(Duration::from_millis(50));
        assert!(process_state(pid).starts_with("T"));

        resume_process(pid).unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }
}
