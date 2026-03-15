use anyhow::{bail, Context};
use std::env;
use std::fs;
use std::io::{self, Read};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        None | Some("snapshot") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&corevanguard_agent::dashboard_snapshot())?
            );
        }
        Some("ingest-json") => {
            let payload = read_payload(args.next().as_deref())?;
            let outcome = corevanguard_agent::ingest_behavioral_event_json(&payload)?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        Some("provider-heartbeat") => {
            let payload = read_payload(args.next().as_deref())?;
            let snapshot = corevanguard_agent::apply_provider_heartbeat_json(&payload)?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Some("replay-jsonl") => {
            let payload = read_payload(args.next().as_deref())?;
            let outcomes = corevanguard_agent::replay_behavioral_events_jsonl(&payload)?;
            println!("{}", serde_json::to_string_pretty(&outcomes)?);
            println!(
                "{}",
                serde_json::to_string_pretty(&corevanguard_agent::dashboard_snapshot())?
            );
        }
        Some(other) => bail!(
            "unknown command '{}'. expected one of: snapshot, ingest-json, provider-heartbeat, replay-jsonl",
            other
        ),
    }

    Ok(())
}

fn read_payload(arg: Option<&str>) -> anyhow::Result<String> {
    match arg {
        Some("-") | None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("failed to read stdin payload")?;
            Ok(buffer)
        }
        Some(path) => fs::read_to_string(path).with_context(|| format!("failed to read {}", path)),
    }
}
