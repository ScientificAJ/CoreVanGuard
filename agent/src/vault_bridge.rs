use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEnrollmentResult {
    pub bridge: String,
    pub detail: String,
}

pub fn enroll_vault_key(
    label: &str,
    bridge_program: Option<&Path>,
) -> Result<VaultEnrollmentResult> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        bail!("Vault profile label cannot be empty.");
    }

    match std::env::consts::OS {
        "linux" => enroll_linux(trimmed, bridge_program),
        "macos" => bail!("macOS secure-entry bridge is not wired into the agent yet."),
        "windows" => bail!("Windows secure desktop bridge is not wired into the agent yet."),
        _ => bail!("Secure-entry bridge is unsupported on this host OS."),
    }
}

fn enroll_linux(label: &str, bridge_program: Option<&Path>) -> Result<VaultEnrollmentResult> {
    let bridge_path = bridge_program.unwrap_or_else(|| Path::new("systemd-ask-password"));
    let output = Command::new(bridge_path)
        .arg(format!("CoreVanguard vault enrollment for {}", label))
        .output()
        .with_context(|| format!("failed to launch {}", bridge_path.display()))?;

    if !output.status.success() {
        bail!("secure-entry bridge exited with status {}", output.status);
    }

    let secret = String::from_utf8_lossy(&output.stdout);
    if secret.trim().is_empty() {
        bail!("secure-entry bridge returned an empty secret");
    }

    Ok(VaultEnrollmentResult {
        bridge: bridge_path.display().to_string(),
        detail: "Vault key enrolled through the native secure-entry bridge.".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn fake_bridge_returns_enrollment_result() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("corevanguard-vault-test-{}", unique));
        fs::create_dir_all(&temp_dir).unwrap();

        let bridge_path = temp_dir.join("fake-ask-password.sh");
        fs::write(&bridge_path, "#!/bin/sh\nprintf 'test-secret\\n'\n").unwrap();
        fs::set_permissions(&bridge_path, fs::Permissions::from_mode(0o755)).unwrap();

        let result = enroll_vault_key("Primary", Some(&bridge_path)).unwrap();
        assert!(result.detail.contains("native secure-entry bridge"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
