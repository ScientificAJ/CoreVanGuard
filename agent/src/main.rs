use anyhow::{bail, Context};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

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
        Some("ingest-json-enforce") => {
            let payload = read_payload(args.next().as_deref())?;
            let result =
                corevanguard_agent::ingest_behavioral_event_with_enforcement_json(&payload)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            println!(
                "{}",
                serde_json::to_string_pretty(&corevanguard_agent::dashboard_snapshot())?
            );
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
        Some("linux-fanotify-guard") => {
            let limit = args
                .next()
                .as_deref()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let paths = args.map(PathBuf::from).collect::<Vec<_>>();
            let report = corevanguard_agent::linux_guard::run_fanotify_guard(&paths, limit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some("bridge-jsonl-run") => {
            let limit = args
                .next()
                .context("bridge-jsonl-run requires a max-events value")?
                .parse::<usize>()
                .context("invalid max-events value")?;
            let program = args
                .next()
                .context("bridge-jsonl-run requires a bridge executable path")?;
            let bridge_args = args.collect::<Vec<_>>();
            let report = corevanguard_agent::process_bridge::run_behavioral_bridge(
                limit,
                Path::new(&program),
                &bridge_args,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some("windows-minifilter-run") => {
            let limit = args
                .next()
                .as_deref()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let report = corevanguard_agent::windows_provider::run_minifilter_bridge(limit)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some("secure-vault-enroll") => {
            let label = args
                .next()
                .context("secure-vault-enroll requires a vault profile label")?;
            let bridge_program = args.next();
            let message = corevanguard_agent::configure_vault_key_secure(
                &label,
                bridge_program.as_deref().map(Path::new),
            )?;
            println!("{}", message);
            println!(
                "{}",
                serde_json::to_string_pretty(&corevanguard_agent::dashboard_snapshot())?
            );
        }
        Some(other) => bail!(
            "unknown command '{}'. expected one of: snapshot, ingest-json, ingest-json-enforce, provider-heartbeat, replay-jsonl, linux-scan, linux-ebpf-json, linux-ebpf-run, linux-fanotify-guard, bridge-jsonl-run, windows-minifilter-run, secure-vault-enroll",
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
