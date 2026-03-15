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

- `agent/` contains the Rust IPC/data contract used by the desktop shell.
- `ui/` contains a real Tauri + React frontend structure with a dashboard, telemetry view, vault settings surface, and diagnostics tab.
- `ui/src-tauri/` exposes Tauri commands and compiles against the shared Rust contract.
- `kernel/linux/` contains a minimal BPF program and build script proving the Linux pipeline shape.
- `kernel/macos/` contains a minimal Endpoint Security compile target proving the macOS pipeline shape.
- `.github/workflows/` contains CI definitions for Windows, Linux, macOS, Tauri, and static analysis.

What does not exist yet:

- Live behavioral telemetry from kernel or user-mode services into the UI
- A checked-in Windows WDK solution/project
- Production signing/notarization material
- The native secure-entry bridge for vault key enrollment
- Real interception logic, rollback logic, or cross-platform policy enforcement

## Repo Notes

- The frontend consumes an availability-based dashboard contract and only renders live telemetry when a provider is actually attached.
- The Windows workflow expects `kernel/windows/CoreVanguardMiniFilter.sln` once you add the real driver project.
- Signing preparation lives in [docs/security/code-signing.md](docs/security/code-signing.md).

## Bootstrap

### Rust

```bash
cargo check -p corevanguard-agent
```

### UI

```bash
cd ui
npm install
npm run tauri:dev
```

## Signing Prep

Production signing is intentionally not wired to local files. Configure GitHub Actions secrets described in [docs/security/code-signing.md](docs/security/code-signing.md) before enabling release signing.
