import type { DashboardSnapshot } from "./types";

const browserPreviewSnapshot: DashboardSnapshot = {
  contract_version: 1,
  provider: "browser_preview",
  generated_at_unix: Math.floor(Date.now() / 1000),
  platform: navigator.userAgent,
  status: "monitoring",
  headline: "Browser preview only",
  message:
    "This view is not attached to Tauri IPC, the Rust agent, or any kernel provider. It only renders the real dashboard contract shape.",
  services: [
    {
      label: "Desktop IPC",
      state: "offline",
      detail: "Browser preview cannot call the Tauri command bridge."
    },
    {
      label: "Kernel providers",
      state: "offline",
      detail: "No Windows, Linux, or macOS kernel producer is attached in browser preview."
    },
    {
      label: "Telemetry ingest",
      state: "offline",
      detail: "No live execution DNA or scheduler stream is available in browser preview."
    }
  ],
  telemetry: {
    state: "offline",
    reason: "No scheduler feed is available in browser preview.",
    points: []
  },
  diagnostics: {
    state: "offline",
    reason: "No live detection feed is available in browser preview.",
    events: []
  },
  vault: {
    state: "unconfigured",
    detail: "Native secure-entry is unavailable outside the desktop shell."
  }
};

export async function getDashboardSnapshot(): Promise<DashboardSnapshot> {
  if (!(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
    return browserPreviewSnapshot;
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<DashboardSnapshot>("get_dashboard_snapshot");
}

export async function enrollVaultKey(label: string): Promise<string> {
  if (!(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
    throw new Error("Native secure-entry is unavailable in browser preview.");
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<string>("configure_vault_key", { label });
}
