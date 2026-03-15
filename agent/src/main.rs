use anyhow::{bail, Context};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

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
        Some("linux-scan") => {
            let limit = args
                .next()
                .as_deref()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16);
            let report = corevanguard_agent::linux_provider::run_host_scan(limit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some("linux-ebpf-json") => {
            let payload = read_payload(args.next().as_deref())?;
            let outcomes = corevanguard_agent::linux_provider::ingest_bpf_jsonl(&payload)?;
            println!("{}", serde_json::to_string_pretty(&outcomes)?);
            println!(
                "{}",
                serde_json::to_string_pretty(&corevanguard_agent::dashboard_snapshot())?
            );
        }
        Some("linux-ebpf-run") => {
            let limit = args
                .next()
                .as_deref()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16);
            let loader_path = args.next();
            let object_path = args.next();
            let report = corevanguard_agent::linux_provider::run_ebpf_loader(
                limit,
                loader_path.as_deref().map(Path::new),
                object_path.as_deref().map(Path::new),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some(other) => bail!(
            "unknown command '{}'. expected one of: snapshot, ingest-json, provider-heartbeat, replay-jsonl, linux-scan, linux-ebpf-json, linux-ebpf-run",
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
