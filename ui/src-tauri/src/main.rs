#[tauri::command]
fn get_dashboard_snapshot() -> corevanguard_agent::DashboardSnapshot {
    corevanguard_agent::dashboard_snapshot()
}

#[tauri::command]
fn ingest_behavioral_event(event_json: String) -> Result<corevanguard_agent::DecisionOutcome, String> {
    corevanguard_agent::ingest_behavioral_event_json(&event_json).map_err(|error| error.to_string())
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_dashboard_snapshot,
            ingest_behavioral_event,
            register_provider_heartbeat,
            configure_vault_key
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CoreVanguard shell");
}
