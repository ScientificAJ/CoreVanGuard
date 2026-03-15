use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    Secure,
    Monitoring,
    Lockdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataMode {
    Seeded,
    Live,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusCard {
    pub label: String,
    pub value: String,
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
pub struct DetectionEvent {
    pub title: String,
    pub severity: String,
    pub origin: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub data_mode: DataMode,
    pub data_note: String,
    pub status: ProtectionLevel,
    pub headline: String,
    pub message: String,
    pub cards: Vec<StatusCard>,
    pub telemetry: Vec<TelemetryPoint>,
    pub detections: Vec<DetectionEvent>,
}

pub fn dashboard_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        data_mode: DataMode::Seeded,
        data_note: "Seeded telemetry for UI and IPC integration. Replace with live agent data before shipping."
            .to_string(),
        status: ProtectionLevel::Secure,
        headline: "Core defenses active".to_string(),
        message: "Execution DNA and hardware-aware scheduling are operating inside nominal thresholds."
            .to_string(),
        cards: vec![
            StatusCard {
                label: "Behavior graph".to_string(),
                value: "2.3M".to_string(),
                detail: "Execution edges correlated in the last 24h".to_string(),
            },
            StatusCard {
                label: "Adaptive threading".to_string(),
                value: "91%".to_string(),
                detail: "Tier 3 analysis kept on efficiency cores".to_string(),
            },
            StatusCard {
                label: "Emergency file locking".to_string(),
                value: "Ready".to_string(),
                detail: "Vault key path staged for secure desktop entry".to_string(),
            },
        ],
        telemetry: vec![
            TelemetryPoint {
                slot: "09:00".to_string(),
                performance_cores: 72,
                efficiency_cores: 26,
                background_jobs: 18,
            },
            TelemetryPoint {
                slot: "10:00".to_string(),
                performance_cores: 64,
                efficiency_cores: 37,
                background_jobs: 24,
            },
            TelemetryPoint {
                slot: "11:00".to_string(),
                performance_cores: 58,
                efficiency_cores: 49,
                background_jobs: 31,
            },
            TelemetryPoint {
                slot: "12:00".to_string(),
                performance_cores: 61,
                efficiency_cores: 52,
                background_jobs: 33,
            },
            TelemetryPoint {
                slot: "13:00".to_string(),
                performance_cores: 55,
                efficiency_cores: 63,
                background_jobs: 38,
            },
        ],
        detections: vec![
            DetectionEvent {
                title: "Unsigned memory injector".to_string(),
                severity: "medium".to_string(),
                origin: "powershell.exe -> child thread anomaly".to_string(),
                action: "Monitored with execution DNA capture".to_string(),
            },
            DetectionEvent {
                title: "Ransomware canary".to_string(),
                severity: "low".to_string(),
                origin: "Simulated vault directory write burst".to_string(),
                action: "EFL pre-lock triggered in 12 ms".to_string(),
            },
        ],
    }
}

pub fn configure_vault_key(_label: &str) -> anyhow::Result<&'static str> {
    Ok("Secure key enrollment UI exists, but the native secure-entry bridge is not wired yet.")
}
