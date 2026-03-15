fn main() -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&corevanguard_agent::dashboard_snapshot())?
    );
    Ok(())
}

