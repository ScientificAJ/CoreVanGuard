export type ProtectionLevel = "secure" | "monitoring" | "lockdown";
export type ComponentState = "online" | "offline" | "degraded" | "unconfigured";
export type ContractProvider = "desktop_contract" | "browser_preview";

export interface ServiceStatus {
  label: string;
  state: ComponentState;
  detail: string;
}

export interface TelemetryPoint {
  slot: string;
  performance_cores: number;
  efficiency_cores: number;
  background_jobs: number;
}

export interface DetectionEvent {
  title: string;
  severity: string;
  origin: string;
  action: string;
}

export interface TelemetryFeed {
  state: ComponentState;
  reason: string;
  points: TelemetryPoint[];
}

export interface DiagnosticsFeed {
  state: ComponentState;
  reason: string;
  events: DetectionEvent[];
}

export interface VaultStatus {
  state: ComponentState;
  detail: string;
}

export interface DashboardSnapshot {
  contract_version: number;
  provider: ContractProvider;
  generated_at_unix: number;
  platform: string;
  status: ProtectionLevel;
  headline: string;
  message: string;
  services: ServiceStatus[];
  telemetry: TelemetryFeed;
  diagnostics: DiagnosticsFeed;
  vault: VaultStatus;
}
