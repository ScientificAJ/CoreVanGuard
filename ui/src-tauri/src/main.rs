use std::path::Path;

#[tauri::command]
fn get_dashboard_snapshot() -> corevanguard_agent::DashboardSnapshot {
    corevanguard_agent::dashboard_snapshot()
}

#[tauri::command]
fn run_linux_provider_scan(limit: Option<usize>) -> Result<serde_json::Value, String> {
    let report = corevanguard_agent::linux_provider::run_host_scan(limit.unwrap_or(16))
        .map_err(|error| error.to_string())?;
    serde_json::to_value(report).map_err(|error| error.to_string())
}

#[tauri::command]
fn run_linux_ebpf_loader(
    limit: Option<usize>,
    loader_path: Option<String>,
    object_path: Option<String>,
) -> Result<serde_json::Value, String> {
    let report = corevanguard_agent::linux_provider::run_ebpf_loader(
        limit.unwrap_or(16),
        loader_path.as_deref().map(Path::new),
        object_path.as_deref().map(Path::new),
    )
    .map_err(|error| error.to_string())?;
    serde_json::to_value(report).map_err(|error| error.to_string())
}

#[tauri::command]
fn ingest_behavioral_event(
    event_json: String,
) -> Result<corevanguard_agent::DecisionOutcome, String> {
    corevanguard_agent::ingest_behavioral_event_json(&event_json).map_err(|error| error.to_string())
}

#[tauri::command]
fn ingest_behavioral_event_with_enforcement(
    event_json: String,
) -> Result<corevanguard_agent::IngestEnforcementResult, String> {
    corevanguard_agent::ingest_behavioral_event_with_enforcement_json(&event_json)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn register_provider_heartbeat(
    heartbeat_json: String,
) -> Result<corevanguard_agent::DashboardSnapshot, String> {
    corevanguard_agent::apply_provider_heartbeat_json(&heartbeat_json)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn configure_vault_key(label: String) -> Result<String, String> {
    corevanguard_agent::configure_vault_key(&label)
        .map(|message| message.to_string())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn configure_vault_key_secure(
    label: String,
    bridge_program: Option<String>,
) -> Result<String, String> {
    corevanguard_agent::configure_vault_key_secure(&label, bridge_program.as_deref().map(Path::new))
        .map_err(|error| error.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_dashboard_snapshot,
            run_linux_provider_scan,
            run_linux_ebpf_loader,
            ingest_behavioral_event,
            ingest_behavioral_event_with_enforcement,
            register_provider_heartbeat,
            configure_vault_key,
            configure_vault_key_secure
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CoreVanguard shell");
}
