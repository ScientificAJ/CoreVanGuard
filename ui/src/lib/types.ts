export type ProtectionLevel = "secure" | "monitoring" | "lockdown";
export type DataMode = "seeded" | "live";

export interface StatusCard {
  label: string;
  value: string;
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

export interface DashboardSnapshot {
  data_mode: DataMode;
  data_note: string;
  status: ProtectionLevel;
  headline: string;
  message: string;
  cards: StatusCard[];
  telemetry: TelemetryPoint[];
  detections: DetectionEvent[];
}
