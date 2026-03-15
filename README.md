# CoreVanguard NGAV

CoreVanguard is a monorepo for a next-generation antivirus stack that splits kernel interception, a Rust control plane, and a Tauri desktop experience into separate delivery surfaces.

## Layout

```text
.
├── agent/                  # Cross-platform Rust control plane
├── docs/security/          # Signing and release hardening notes
├── kernel/
│   ├── linux/              # eBPF / LSM sources
│   ├── macos/              # Endpoint Security sources
│   └── windows/            # MiniFilter / KMDF sources
├── scripts/                # CI-friendly build helpers
└── ui/
    ├── src/                # React/Tailwind frontend
    └── src-tauri/          # Tauri Rust bridge
```

## Implementation Status

This repository is an honest starter, not a finished antivirus engine. What exists today:

- `agent/` contains a real engine core with provider registration, behavioral event ingestion, tiered scoring, stateful process risk tracking, JSON replay support, and dashboard snapshot generation.
- `agent/src/linux_provider.rs` performs a real Linux host scan from `/proc`, maps live sockets, inspects executable memory regions, registers provider heartbeats, and feeds observations into the engine.
- `ui/` contains a real Tauri + React frontend structure with a dashboard, telemetry view, vault settings surface, and diagnostics tab.
- `ui/src-tauri/` exposes Tauri commands against the shared Rust engine contract, including snapshot retrieval, provider heartbeats, and behavioral event ingestion.
- `kernel/linux/` contains an actual eBPF syscall monitor for exec/open/write/kill/ptrace plus the Linux build script.
- `kernel/windows/` contains a real MiniFilter source file with create/write/set-information callbacks and protected-path denial logic.
- `kernel/macos/` contains an Endpoint Security subscriber target for exec/open/signal/ptrace notifications.
- `.github/workflows/` contains CI definitions for Windows, Linux, macOS, Tauri, and static analysis.

What does not exist yet:

- Production-ready transport from the native Windows/macOS adapters into the Rust engine
- A checked-in Windows WDK solution/project
- Production signing/notarization material
- The native secure-entry bridge for vault key enrollment
- Cross-platform enforcement adapters for block, freeze, or lockdown actions

## Repo Notes

- The frontend consumes an availability-based dashboard contract and only renders live telemetry when a provider is actually attached.
- The Windows workflow expects `kernel/windows/CoreVanguardMiniFilter.sln` once you add the real driver project.
- Signing preparation lives in [docs/security/code-signing.md](docs/security/code-signing.md).

## Bootstrap

### Rust

```bash
cargo check -p corevanguard-agent
cargo test -p corevanguard-agent
cargo run -p corevanguard-agent -- snapshot
cargo run -p corevanguard-agent -- linux-scan 8
```

### UI

```bash
cd ui
npm install
npm run tauri:dev
```

### Event Replay

```bash
cargo run -p corevanguard-agent -- replay-jsonl events.jsonl
```

## Signing Prep

Production signing is intentionally not wired to local files. Configure GitHub Actions secrets described in [docs/security/code-signing.md](docs/security/code-signing.md) before enabling release signing.
