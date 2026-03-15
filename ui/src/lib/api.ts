import type { DashboardSnapshot } from "./types";

const fallbackSnapshot: DashboardSnapshot = {
  data_mode: "seeded",
  data_note:
    "Browser preview is using seeded telemetry because the Tauri shell and live agent bridge are not active.",
  status: "secure",
  headline: "Core defenses active",
  message:
    "Execution DNA and hardware-aware scheduling are operating inside nominal thresholds.",
  cards: [
    {
      label: "Behavior graph",
      value: "2.3M",
      detail: "Execution edges correlated in the last 24h"
    },
    {
      label: "Adaptive threading",
      value: "91%",
      detail: "Tier 3 analysis kept on efficiency cores"
    },
    {
      label: "Emergency file locking",
      value: "Ready",
      detail: "Vault key path staged for secure desktop entry"
    }
  ],
  telemetry: [
    { slot: "09:00", performance_cores: 72, efficiency_cores: 26, background_jobs: 18 },
    { slot: "10:00", performance_cores: 64, efficiency_cores: 37, background_jobs: 24 },
    { slot: "11:00", performance_cores: 58, efficiency_cores: 49, background_jobs: 31 },
    { slot: "12:00", performance_cores: 61, efficiency_cores: 52, background_jobs: 33 },
    { slot: "13:00", performance_cores: 55, efficiency_cores: 63, background_jobs: 38 }
  ],
  detections: [
    {
      title: "Unsigned memory injector",
      severity: "medium",
      origin: "powershell.exe -> child thread anomaly",
      action: "Monitored with execution DNA capture"
    },
    {
      title: "Ransomware canary",
      severity: "low",
      origin: "Simulated vault directory write burst",
      action: "EFL pre-lock triggered in 12 ms"
    }
  ]
};

export async function getDashboardSnapshot(): Promise<DashboardSnapshot> {
  if (!(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
    return fallbackSnapshot;
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<DashboardSnapshot>("get_dashboard_snapshot");
}

export async function enrollVaultKey(label: string): Promise<string> {
  if (!(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
    return "Secure key enrollment is unavailable in browser preview because the native secure-entry bridge is not active.";
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<string>("configure_vault_key", { label });
}
