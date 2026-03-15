use crate::{
    dashboard_snapshot, ingest_behavioral_event, BehavioralEvent, DashboardSnapshot,
    DecisionOutcome,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBridgeReport {
    pub program: String,
    pub events_observed: usize,
    pub decisions: Vec<DecisionOutcome>,
    pub snapshot: DashboardSnapshot,
}

pub fn run_behavioral_bridge(
    max_events: usize,
    program: &Path,
    args: &[String],
) -> Result<ProcessBridgeReport> {
    if !program.is_file() {
        bail!("bridge executable not found: {}", program.display());
    }

    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn {}", program.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("failed to capture bridge stdout")?;
    let reader = BufReader::new(stdout);

    let mut events_observed = 0usize;
    let mut decisions = Vec::new();

    for line in reader.lines() {
        let line = line.context("failed to read bridge output")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: BehavioralEvent = serde_json::from_str(trimmed)
            .with_context(|| format!("invalid bridge event: {}", trimmed))?;
        decisions.push(ingest_behavioral_event(event)?);
        events_observed += 1;

        if max_events > 0 && events_observed >= max_events {
            break;
        }
    }

    let _ = child.kill();
    let status = child.wait().context("failed waiting for bridge process")?;
    if events_observed == 0 && !status.success() {
        bail!("bridge exited without events: {}", status);
    }

    Ok(ProcessBridgeReport {
        program: program.display().to_string(),
        events_observed,
        decisions,
        snapshot: dashboard_snapshot(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn behavioral_bridge_ingests_jsonl_output() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("corevanguard-bridge-test-{}", unique));
        fs::create_dir_all(&temp_dir).unwrap();

        let bridge_path = temp_dir.join("fake-bridge.sh");
        let pid = std::process::id();
        let script = format!(
            "#!/bin/sh\nprintf '{{\"kind\":\"self_protection_event\",\"provider_id\":\"linux.ebpf_guard\",\"process_id\":{pid},\"process_name\":\"bridge-test\",\"target\":\"corevanguard-agent\",\"technique\":\"ptrace\"}}\\n'\n"
        );

        fs::write(&bridge_path, script).unwrap();
        fs::set_permissions(&bridge_path, fs::Permissions::from_mode(0o755)).unwrap();

        let report = run_behavioral_bridge(1, &bridge_path, &[]).unwrap();
        assert_eq!(report.events_observed, 1);
        assert_eq!(report.decisions.len(), 1);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
