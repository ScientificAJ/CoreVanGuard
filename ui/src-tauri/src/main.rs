#[tauri::command]
fn get_dashboard_snapshot() -> corevanguard_agent::DashboardSnapshot {
    corevanguard_agent::dashboard_snapshot()
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
            configure_vault_key
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CoreVanguard shell");
}
