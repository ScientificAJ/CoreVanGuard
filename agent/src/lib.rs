use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    Secure,
    Monitoring,
    Lockdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Online,
    Offline,
    Degraded,
    Unconfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractProvider {
    DesktopContract,
    BrowserPreview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub label: String,
    pub state: ComponentState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPoint {
    pub slot: String,
    pub performance_cores: u8,
    pub efficiency_cores: u8,
    pub background_jobs: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryFeed {
    pub state: ComponentState,
    pub reason: String,
    pub points: Vec<TelemetryPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub title: String,
    pub severity: String,
    pub origin: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsFeed {
    pub state: ComponentState,
    pub reason: String,
    pub events: Vec<DetectionEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub state: ComponentState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub contract_version: u16,
    pub provider: ContractProvider,
    pub generated_at_unix: u64,
    pub platform: String,
    pub status: ProtectionLevel,
    pub headline: String,
    pub message: String,
    pub services: Vec<ServiceStatus>,
    pub telemetry: TelemetryFeed,
    pub diagnostics: DiagnosticsFeed,
    pub vault: VaultStatus,
}

pub fn dashboard_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        contract_version: 1,
        provider: ContractProvider::DesktopContract,
        generated_at_unix: unix_timestamp_secs(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        status: ProtectionLevel::Monitoring,
        headline: "Control plane online".to_string(),
        message:
            "Desktop IPC is reachable, but kernel providers and live telemetry streams are not registered yet."
                .to_string(),
        services: vec![
            ServiceStatus {
                label: "Desktop IPC".to_string(),
                state: ComponentState::Online,
                detail: "Tauri commands can reach the embedded control-plane contract."
                    .to_string(),
            },
            ServiceStatus {
                label: "Kernel providers".to_string(),
                state: ComponentState::Offline,
                detail:
                    "No Windows MiniFilter, Linux eBPF, or macOS Endpoint Security producer is attached."
                        .to_string(),
            },
            ServiceStatus {
                label: "Telemetry ingest".to_string(),
                state: ComponentState::Offline,
                detail:
                    "Execution DNA, scheduler samples, and detection events will appear after providers publish into the agent."
                        .to_string(),
            },
        ],
        telemetry: TelemetryFeed {
            state: ComponentState::Offline,
            reason: "No live scheduler feed is attached to the agent yet.".to_string(),
            points: Vec::new(),
        },
        diagnostics: DiagnosticsFeed {
            state: ComponentState::Offline,
            reason: "No detection or execution-DNA feed is attached to the agent yet.".to_string(),
            events: Vec::new(),
        },
        vault: VaultStatus {
            state: ComponentState::Unconfigured,
            detail: "The native secure-entry bridge is not implemented on this platform yet."
                .to_string(),
        },
    }
}

pub fn configure_vault_key(_label: &str) -> anyhow::Result<&'static str> {
    anyhow::bail!("Native secure-entry bridge is not implemented yet.")
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
