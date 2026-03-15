use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod enforcement;
pub mod linux_provider;
pub mod vault_bridge;

const CONTRACT_VERSION: u16 = 2;
const MAX_DECISIONS: usize = 24;
const MAX_TELEMETRY_POINTS: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    Secure,
    Monitoring,
    Lockdown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Online,
    Offline,
    Degraded,
    Unconfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractProvider {
    DesktopContract,
    BrowserPreview,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulingMode {
    Relaxed,
    Balanced,
    HighThroughput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDomain {
    Agent,
    WindowsKernel,
    LinuxKernel,
    MacosEndpointSecurity,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    FileInterception,
    ThreadOriginValidation,
    NetworkInterception,
    SelfProtection,
    PrivilegeMonitoring,
    VaultBridge,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    Trusted,
    Unsigned,
    Tampered,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadOrigin {
    Image,
    Heap,
    Jit,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reputation {
    Trusted,
    Unknown,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfProtectionTechnique {
    KillSignal,
    Ptrace,
    HandleOpen,
    UnloadAttempt,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationVector {
    TccPrompt,
    Setuid,
    TokenTheft,
    ServiceInstall,
    LaunchAgent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Observe,
    Escalate,
    BlockOperation,
    FreezeProcess,
    EmergencyLockdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHeartbeat {
    pub id: String,
    pub label: String,
    pub domain: ProviderDomain,
    pub capabilities: Vec<ProviderCapability>,
    pub state: ComponentState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub label: String,
    pub state: ComponentState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPoint {
    pub slot: String,
    pub performance_cores: u8,
    pub efficiency_cores: u8,
    pub background_jobs: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryFeed {
    pub state: ComponentState,
    pub reason: String,
    pub points: Vec<TelemetryPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub title: String,
    pub severity: String,
    pub origin: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsFeed {
    pub state: ComponentState,
    pub reason: String,
    pub events: Vec<DetectionEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub state: ComponentState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub contract_version: u16,
    pub provider: ContractProvider,
    pub generated_at_unix: u64,
    pub platform: String,
    pub status: ProtectionLevel,
    pub headline: String,
    pub message: String,
    pub services: Vec<ServiceStatus>,
    pub telemetry: TelemetryFeed,
    pub diagnostics: DiagnosticsFeed,
    pub vault: VaultStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutcome {
    pub process_id: u32,
    pub process_name: String,
    pub provider_id: String,
    pub tier1_score: i32,
    pub tier2_score: i32,
    pub tier3_score: i32,
    pub total_score: i32,
    pub action: DecisionAction,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestEnforcementResult {
    pub decision: DecisionOutcome,
    pub enforcement: enforcement::EnforcementReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BehavioralEvent {
    ExecutionStart {
        provider_id: String,
        process_id: u32,
        process_name: String,
        image_path: String,
        parent_process: Option<String>,
        launched_from_user_space: bool,
        signature_state: SignatureState,
        requested_persistence: bool,
    },
    ThreadInspection {
        provider_id: String,
        process_id: u32,
        process_name: String,
        target_process: String,
        target_critical: bool,
        cross_process: bool,
        origin: ThreadOrigin,
    },
    FileMutation {
        provider_id: String,
        process_id: u32,
        process_name: String,
        path: String,
        bytes_written: u64,
        entropy: f32,
        protected_path: bool,
        canary_file: bool,
    },
    NetworkConnection {
        provider_id: String,
        process_id: u32,
        process_name: String,
        remote_address: String,
        remote_port: u16,
        encrypted: bool,
        reputation: Reputation,
        beacon_interval_seconds: Option<u16>,
    },
    SelfProtectionEvent {
        provider_id: String,
        process_id: u32,
        process_name: String,
        target: String,
        technique: SelfProtectionTechnique,
    },
    ModuleIntegrity {
        provider_id: String,
        process_id: u32,
        process_name: String,
        module_name: String,
        kernel_surface: bool,
        unsigned: bool,
        patched: bool,
    },
    PrivilegeEscalation {
        provider_id: String,
        process_id: u32,
        process_name: String,
        target: String,
        vector: EscalationVector,
        tcc_bypass_attempt: bool,
    },
}

#[derive(Debug, Clone)]
struct HostProfile {
    logical_cpus: u16,
    performance_lanes: u16,
    efficiency_lanes: u16,
    scheduling_mode: SchedulingMode,
}

#[derive(Debug, Clone)]
struct ProviderRuntime {
    label: String,
    domain: ProviderDomain,
    capabilities: Vec<ProviderCapability>,
    state: ComponentState,
    detail: String,
    last_heartbeat_unix: Option<u64>,
}

#[derive(Debug, Clone)]
struct ProcessLedger {
    process_name: String,
    cumulative_score: i32,
    event_count: u32,
    high_entropy_writes: u32,
    cross_process_threads: u32,
    beacon_count: u32,
    last_seen_unix: u64,
    last_action: DecisionAction,
}

#[derive(Debug, Clone)]
struct DecisionRecord {
    title: String,
    severity: String,
    origin: String,
    action: DecisionAction,
    reasons: Vec<String>,
    total_score: i32,
}

#[derive(Debug, Clone)]
struct VaultRuntime {
    state: ComponentState,
    detail: String,
    configured_label: Option<String>,
}

#[derive(Debug)]
pub struct CoreVanguardEngine {
    host: HostProfile,
    providers: HashMap<String, ProviderRuntime>,
    ledgers: HashMap<u32, ProcessLedger>,
    recent_decisions: VecDeque<DecisionRecord>,
    telemetry_points: VecDeque<TelemetryPoint>,
    processed_events: u64,
    active_lockdowns: u32,
    vault: VaultRuntime,
}

static ENGINE: OnceLock<Mutex<CoreVanguardEngine>> = OnceLock::new();

impl CoreVanguardEngine {
    pub fn new() -> Self {
        let host = detect_host_profile();
        let mut engine = Self {
            host,
            providers: HashMap::new(),
            ledgers: HashMap::new(),
            recent_decisions: VecDeque::new(),
            telemetry_points: VecDeque::new(),
            processed_events: 0,
            active_lockdowns: 0,
            vault: VaultRuntime {
                state: ComponentState::Unconfigured,
                detail: "Native secure-entry bridge has not been attached.".to_string(),
                configured_label: None,
            },
        };

        engine.register_builtin_providers();
        engine.record_scheduler_sample();
        engine
    }

    pub fn dashboard_snapshot(&mut self) -> DashboardSnapshot {
        self.record_scheduler_sample();

        let provider_service = self.provider_mesh_service();
        let pipeline_service = self.pipeline_service();
        let control_plane_service = self.control_plane_service();

        let status = if self.active_lockdowns > 0 {
            ProtectionLevel::Lockdown
        } else if provider_service.state != ComponentState::Online
            || self
                .recent_decisions
                .iter()
                .any(|decision| decision.action >= DecisionAction::Escalate)
        {
            ProtectionLevel::Monitoring
        } else {
            ProtectionLevel::Secure
        };

        let (headline, message) =
            self.headline_and_message(&status, &provider_service, &pipeline_service);

        DashboardSnapshot {
            contract_version: CONTRACT_VERSION,
            provider: ContractProvider::DesktopContract,
            generated_at_unix: unix_timestamp_secs(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            status,
            headline,
            message,
            services: vec![control_plane_service, provider_service, pipeline_service],
            telemetry: self.telemetry_feed(),
            diagnostics: self.diagnostics_feed(),
            vault: VaultStatus {
                state: self.vault.state,
                detail: match &self.vault.configured_label {
                    Some(label) => format!("{} Requested profile: {}.", self.vault.detail, label),
                    None => self.vault.detail.clone(),
                },
            },
        }
    }

    pub fn apply_provider_heartbeat(&mut self, heartbeat: ProviderHeartbeat) {
        self.providers.insert(
            heartbeat.id,
            ProviderRuntime {
                label: heartbeat.label,
                domain: heartbeat.domain,
                capabilities: heartbeat.capabilities,
                state: heartbeat.state,
                detail: heartbeat.detail,
                last_heartbeat_unix: Some(unix_timestamp_secs()),
            },
        );
    }

    pub fn ingest_behavioral_event(&mut self, event: BehavioralEvent) -> DecisionOutcome {
        self.processed_events += 1;
        self.ensure_provider_for_event(&event);

        let now = unix_timestamp_secs();
        let process_id = event.process_id();
        let process_name = event.process_name().to_string();
        let provider_id = event.provider_id().to_string();

        let ledger = self
            .ledgers
            .entry(process_id)
            .or_insert_with(|| ProcessLedger {
                process_name: process_name.clone(),
                cumulative_score: 0,
                event_count: 0,
                high_entropy_writes: 0,
                cross_process_threads: 0,
                beacon_count: 0,
                last_seen_unix: now,
                last_action: DecisionAction::Observe,
            });

        ledger.process_name = process_name.clone();
        ledger.last_seen_unix = now;
        ledger.event_count += 1;

        let mut tier1_score = 0;
        let mut tier2_score = 0;
        let mut tier3_score = 0;
        let mut forced_action: Option<DecisionAction> = None;
        let mut reasons = Vec::new();

        match &event {
            BehavioralEvent::ExecutionStart {
                image_path,
                launched_from_user_space,
                signature_state,
                requested_persistence,
                ..
            } => {
                if *launched_from_user_space {
                    tier1_score += 12;
                    reasons.push(format!("execution from user-writable path: {}", image_path));
                }

                match signature_state {
                    SignatureState::Trusted => {}
                    SignatureState::Unsigned => {
                        tier1_score += 18;
                        reasons.push("unsigned executable requested execution".to_string());
                    }
                    SignatureState::Tampered => {
                        tier2_score += 28;
                        reasons.push("tampered executable signature observed".to_string());
                    }
                }

                if *requested_persistence {
                    tier2_score += 20;
                    reasons.push("persistence mechanism requested during execution".to_string());
                }
            }
            BehavioralEvent::ThreadInspection {
                target_process,
                target_critical,
                cross_process,
                origin,
                ..
            } => {
                if *cross_process {
                    tier1_score += 16;
                    ledger.cross_process_threads += 1;
                    reasons.push(format!(
                        "cross-process thread activity against {}",
                        target_process
                    ));
                }

                match origin {
                    ThreadOrigin::Image => {}
                    ThreadOrigin::Jit => {
                        tier1_score += 6;
                        reasons.push("thread originated from JIT memory".to_string());
                    }
                    ThreadOrigin::Heap => {
                        tier2_score += 34;
                        reasons.push("thread originated from heap memory".to_string());
                    }
                    ThreadOrigin::Unknown => {
                        tier2_score += 26;
                        reasons.push("thread origin could not be validated".to_string());
                    }
                }

                if *target_critical {
                    tier3_score += 24;
                    reasons.push(format!("critical target engaged: {}", target_process));
                    if matches!(origin, ThreadOrigin::Heap | ThreadOrigin::Unknown) {
                        forced_action = Some(DecisionAction::EmergencyLockdown);
                    }
                }
            }
            BehavioralEvent::FileMutation {
                path,
                bytes_written,
                entropy,
                protected_path,
                canary_file,
                ..
            } => {
                if *bytes_written > 256 * 1024 {
                    tier1_score += 10;
                    reasons.push(format!("large write burst detected at {}", path));
                }

                if *entropy >= 7.2 {
                    tier2_score += 18;
                    ledger.high_entropy_writes += 1;
                    reasons.push(format!("high-entropy write pattern at {}", path));
                }

                if *protected_path {
                    tier2_score += 20;
                    reasons.push("write targeted a protected path".to_string());
                }

                if ledger.high_entropy_writes >= 3 {
                    tier3_score += 18;
                    reasons.push("repeated high-entropy write behavior accumulated".to_string());
                }

                if *canary_file {
                    tier3_score += 42;
                    reasons.push("ransomware canary was touched".to_string());
                    forced_action = Some(DecisionAction::EmergencyLockdown);
                    self.vault.state = ComponentState::Degraded;
                    self.vault.detail =
                        "Emergency file locking signal detected, but the secure-entry bridge is still missing."
                            .to_string();
                }
            }
            BehavioralEvent::NetworkConnection {
                remote_address,
                remote_port,
                reputation,
                beacon_interval_seconds,
                ..
            } => {
                match reputation {
                    Reputation::Trusted => {}
                    Reputation::Unknown => {
                        tier1_score += 6;
                        reasons.push(format!(
                            "outbound connection to unclassified destination {}:{}",
                            remote_address, remote_port
                        ));
                    }
                    Reputation::Suspicious => {
                        tier1_score += 18;
                        tier2_score += 10;
                        reasons.push(format!(
                            "outbound connection to suspicious destination {}:{}",
                            remote_address, remote_port
                        ));
                    }
                    Reputation::Malicious => {
                        tier2_score += 26;
                        tier3_score += 18;
                        reasons.push(format!(
                            "outbound connection to malicious destination {}:{}",
                            remote_address, remote_port
                        ));
                    }
                }

                if let Some(interval) = beacon_interval_seconds {
                    ledger.beacon_count += 1;
                    if *interval <= 120 {
                        tier2_score += 14;
                        reasons.push(format!(
                            "beacon cadence detected every {} seconds",
                            interval
                        ));
                    }
                }

                if ledger.beacon_count >= 3 {
                    tier3_score += 10;
                    reasons.push("repeated beacon-like traffic pattern accumulated".to_string());
                }
            }
            BehavioralEvent::SelfProtectionEvent {
                target, technique, ..
            } => {
                tier1_score += 18;
                tier2_score += 18;
                reasons.push(format!("self-protection violation against {}", target));

                match technique {
                    SelfProtectionTechnique::HandleOpen => {
                        tier1_score += 8;
                    }
                    SelfProtectionTechnique::KillSignal
                    | SelfProtectionTechnique::Ptrace
                    | SelfProtectionTechnique::UnloadAttempt => {
                        tier3_score += 24;
                        forced_action = Some(DecisionAction::FreezeProcess);
                    }
                }
            }
            BehavioralEvent::ModuleIntegrity {
                module_name,
                kernel_surface,
                unsigned,
                patched,
                ..
            } => {
                if *unsigned {
                    tier1_score += 16;
                    reasons.push(format!("unsigned module observed: {}", module_name));
                }

                if *kernel_surface {
                    tier2_score += 18;
                    reasons.push(format!("kernel-surface tamper candidate: {}", module_name));
                }

                if *patched {
                    tier3_score += 28;
                    reasons.push(format!("runtime patching detected on {}", module_name));
                    forced_action = Some(DecisionAction::FreezeProcess);
                }
            }
            BehavioralEvent::PrivilegeEscalation {
                target,
                vector,
                tcc_bypass_attempt,
                ..
            } => {
                tier1_score += 12;
                reasons.push(format!("privilege escalation path targeting {}", target));

                match vector {
                    EscalationVector::TccPrompt => tier2_score += 10,
                    EscalationVector::Setuid => tier2_score += 14,
                    EscalationVector::TokenTheft => tier3_score += 24,
                    EscalationVector::ServiceInstall | EscalationVector::LaunchAgent => {
                        tier2_score += 18
                    }
                }

                if *tcc_bypass_attempt {
                    tier3_score += 16;
                    reasons.push("privacy control bypass attempt detected".to_string());
                }
            }
        }

        let stateful_bonus = (ledger.cumulative_score / 6)
            + if ledger.high_entropy_writes >= 5 {
                12
            } else {
                0
            }
            + if ledger.cross_process_threads >= 2 {
                10
            } else {
                0
            }
            + if ledger.beacon_count >= 3 { 8 } else { 0 };

        let total_score = tier1_score + tier2_score + tier3_score + stateful_bonus;
        let mut action = action_for_score(total_score);
        if let Some(forced) = forced_action {
            action = action.max(forced);
        }

        if action == DecisionAction::EmergencyLockdown {
            self.active_lockdowns = self.active_lockdowns.saturating_add(1);
        }

        ledger.cumulative_score = (ledger.cumulative_score + total_score / 2).clamp(0, 100);
        ledger.last_action = action;

        let outcome = DecisionOutcome {
            process_id,
            process_name: process_name.clone(),
            provider_id,
            tier1_score,
            tier2_score,
            tier3_score,
            total_score,
            action,
            reasons: if reasons.is_empty() {
                vec!["no significant behavioral anomalies detected".to_string()]
            } else {
                reasons
            },
        };

        self.record_decision(&event, &outcome);
        self.record_scheduler_sample();
        outcome
    }

    pub fn configure_vault_key(&mut self, label: &str) -> anyhow::Result<&'static str> {
        if label.trim().is_empty() {
            bail!("Vault profile label cannot be empty.");
        }

        self.vault.configured_label = Some(label.trim().to_string());
        self.vault.state = ComponentState::Degraded;
        self.vault.detail =
            "Secure-entry bridge is still missing, so the vault key cannot be enrolled yet."
                .to_string();
        bail!("Native secure-entry bridge is not implemented yet.")
    }

    pub fn configure_vault_key_secure(
        &mut self,
        label: &str,
        bridge_program: Option<&Path>,
    ) -> anyhow::Result<String> {
        let enrollment = vault_bridge::enroll_vault_key(label, bridge_program)?;
        self.vault.configured_label = Some(label.trim().to_string());
        self.vault.state = ComponentState::Online;
        self.vault.detail = enrollment.detail;
        Ok(format!(
            "Vault key enrolled through secure bridge {}.",
            enrollment.bridge
        ))
    }

    fn register_builtin_providers(&mut self) {
        self.providers.insert(
            "agent.control_plane".to_string(),
            ProviderRuntime {
                label: "Desktop control plane".to_string(),
                domain: ProviderDomain::Agent,
                capabilities: vec![ProviderCapability::SelfProtection],
                state: ComponentState::Online,
                detail: "Rust engine core and IPC contract are online.".to_string(),
                last_heartbeat_unix: Some(unix_timestamp_secs()),
            },
        );

        match std::env::consts::OS {
            "windows" => {
                self.register_expected_provider(
                    "windows.minifilter",
                    "Windows MiniFilter",
                    ProviderDomain::WindowsKernel,
                    vec![ProviderCapability::FileInterception],
                    "Awaiting MiniFilter adapter heartbeat.",
                );
                self.register_expected_provider(
                    "windows.ob_callbacks",
                    "Windows Self-Protection",
                    ProviderDomain::WindowsKernel,
                    vec![ProviderCapability::SelfProtection],
                    "Awaiting process-protection callback adapter heartbeat.",
                );
            }
            "linux" => {
                self.register_expected_provider(
                    "linux.file_gate",
                    "Linux File Gate",
                    ProviderDomain::LinuxKernel,
                    vec![ProviderCapability::FileInterception],
                    "Awaiting fanotify or LSM adapter heartbeat.",
                );
                self.register_expected_provider(
                    "linux.ebpf_guard",
                    "Linux eBPF Guard",
                    ProviderDomain::LinuxKernel,
                    vec![
                        ProviderCapability::SelfProtection,
                        ProviderCapability::ThreadOriginValidation,
                    ],
                    "Awaiting eBPF self-protection adapter heartbeat.",
                );
                self.register_expected_provider(
                    "linux.netfilter",
                    "Linux Netfilter Guard",
                    ProviderDomain::LinuxKernel,
                    vec![ProviderCapability::NetworkInterception],
                    "Awaiting netfilter adapter heartbeat.",
                );
            }
            "macos" => {
                self.register_expected_provider(
                    "macos.endpoint_security",
                    "macOS Endpoint Security",
                    ProviderDomain::MacosEndpointSecurity,
                    vec![
                        ProviderCapability::FileInterception,
                        ProviderCapability::ThreadOriginValidation,
                        ProviderCapability::PrivilegeMonitoring,
                    ],
                    "Awaiting Endpoint Security adapter heartbeat.",
                );
                self.register_expected_provider(
                    "macos.system_extension",
                    "macOS System Extension",
                    ProviderDomain::MacosEndpointSecurity,
                    vec![ProviderCapability::SelfProtection],
                    "Awaiting system extension heartbeat.",
                );
            }
            _ => {
                self.register_expected_provider(
                    "host.kernel_adapter",
                    "Kernel Adapter",
                    ProviderDomain::External,
                    vec![ProviderCapability::FileInterception],
                    "Unsupported host OS for built-in provider bootstrap.",
                );
            }
        }
    }

    fn register_expected_provider(
        &mut self,
        id: &str,
        label: &str,
        domain: ProviderDomain,
        capabilities: Vec<ProviderCapability>,
        detail: &str,
    ) {
        self.providers.insert(
            id.to_string(),
            ProviderRuntime {
                label: label.to_string(),
                domain,
                capabilities,
                state: ComponentState::Offline,
                detail: detail.to_string(),
                last_heartbeat_unix: None,
            },
        );
    }

    fn ensure_provider_for_event(&mut self, event: &BehavioralEvent) {
        let provider_id = event.provider_id().to_string();
        let entry = self
            .providers
            .entry(provider_id.clone())
            .or_insert(ProviderRuntime {
                label: provider_id.clone(),
                domain: ProviderDomain::External,
                capabilities: Vec::new(),
                state: ComponentState::Online,
                detail: "Provider registered dynamically through event ingestion.".to_string(),
                last_heartbeat_unix: Some(unix_timestamp_secs()),
            });

        entry.state = ComponentState::Online;
        entry.last_heartbeat_unix = Some(unix_timestamp_secs());
        if entry.detail.is_empty() {
            entry.detail = "Provider heartbeat implied by live event ingestion.".to_string();
        }
    }

    fn record_decision(&mut self, event: &BehavioralEvent, outcome: &DecisionOutcome) {
        if outcome.action == DecisionAction::Observe && outcome.total_score < 20 {
            return;
        }

        self.recent_decisions.push_front(DecisionRecord {
            title: format!("{} · {}", outcome.process_name, event.short_label()),
            severity: severity_for(outcome.action).to_string(),
            origin: event.origin_summary(),
            action: outcome.action,
            reasons: outcome.reasons.clone(),
            total_score: outcome.total_score,
        });

        while self.recent_decisions.len() > MAX_DECISIONS {
            self.recent_decisions.pop_back();
        }
    }

    fn control_plane_service(&self) -> ServiceStatus {
        ServiceStatus {
            label: "Control plane".to_string(),
            state: ComponentState::Online,
            detail: format!(
                "Contract v{} on {} logical CPUs in {:?} mode.",
                CONTRACT_VERSION, self.host.logical_cpus, self.host.scheduling_mode
            ),
        }
    }

    fn provider_mesh_service(&self) -> ServiceStatus {
        let relevant: Vec<&ProviderRuntime> = self
            .providers
            .values()
            .filter(|provider| !matches!(provider.domain, ProviderDomain::Agent))
            .collect();

        let online = relevant
            .iter()
            .filter(|provider| provider.state == ComponentState::Online)
            .count();

        let state = if relevant.is_empty() {
            ComponentState::Unconfigured
        } else if online == relevant.len() {
            ComponentState::Online
        } else if online > 0 {
            ComponentState::Degraded
        } else {
            ComponentState::Offline
        };

        let labels = relevant
            .iter()
            .map(|provider| format!("{} ({} caps)", provider.label, provider.capabilities.len()))
            .collect::<Vec<_>>()
            .join(", ");

        ServiceStatus {
            label: "Provider mesh".to_string(),
            state,
            detail: format!(
                "{} of {} expected providers online. {}",
                online,
                relevant.len(),
                if labels.is_empty() {
                    "No provider adapters are registered.".to_string()
                } else {
                    format!("Providers: {}", labels)
                }
            ),
        }
    }

    fn pipeline_service(&self) -> ServiceStatus {
        let active_cases = self
            .ledgers
            .values()
            .filter(|ledger| ledger.cumulative_score >= 25)
            .count();

        let state = if self.active_lockdowns > 0 {
            ComponentState::Degraded
        } else {
            ComponentState::Online
        };

        ServiceStatus {
            label: "Tier pipeline".to_string(),
            state,
            detail: format!(
                "Processed {} events. Active cases: {}. Recent alerts: {}.",
                self.processed_events,
                active_cases,
                self.recent_decisions.len()
            ),
        }
    }

    fn headline_and_message(
        &self,
        status: &ProtectionLevel,
        provider_service: &ServiceStatus,
        pipeline_service: &ServiceStatus,
    ) -> (String, String) {
        match status {
            ProtectionLevel::Lockdown => {
                if let Some(decision) = self.recent_decisions.front() {
                    (
                        "Emergency containment active".to_string(),
                        format!("{}. {}", decision.title, decision.reasons.join("; ")),
                    )
                } else {
                    (
                        "Emergency containment active".to_string(),
                        "The engine promoted one or more events into lockdown.".to_string(),
                    )
                }
            }
            ProtectionLevel::Monitoring => (
                "Engine core online".to_string(),
                format!("{} {}", provider_service.detail, pipeline_service.detail),
            ),
            ProtectionLevel::Secure => (
                "Protection pipeline online".to_string(),
                "Providers are healthy and no active behavioral anomalies are being escalated."
                    .to_string(),
            ),
        }
    }

    fn telemetry_feed(&self) -> TelemetryFeed {
        TelemetryFeed {
            state: ComponentState::Online,
            reason: format!(
                "Scheduler allocation derived from {} logical CPUs in {:?} mode.",
                self.host.logical_cpus, self.host.scheduling_mode
            ),
            points: self.telemetry_points.iter().cloned().collect(),
        }
    }

    fn diagnostics_feed(&self) -> DiagnosticsFeed {
        if self.recent_decisions.is_empty() {
            return DiagnosticsFeed {
                state: ComponentState::Offline,
                reason:
                    "No behavioral alerts have been raised yet. Kernel adapters can begin publishing events immediately."
                        .to_string(),
                events: Vec::new(),
            };
        }

        DiagnosticsFeed {
            state: ComponentState::Online,
            reason: format!(
                "{} recent behavioral decisions retained for operator review.",
                self.recent_decisions.len()
            ),
            events: self
                .recent_decisions
                .iter()
                .map(|decision| DetectionEvent {
                    title: decision.title.clone(),
                    severity: decision.severity.clone(),
                    origin: decision.origin.clone(),
                    action: format!(
                        "{} · score {} · {}",
                        action_label(decision.action),
                        decision.total_score,
                        decision.reasons.join("; ")
                    ),
                })
                .collect(),
        }
    }

    fn record_scheduler_sample(&mut self) {
        let active_cases = self
            .ledgers
            .values()
            .filter(|ledger| ledger.cumulative_score >= 25)
            .count() as u32;
        let critical_cases = self
            .ledgers
            .values()
            .filter(|ledger| ledger.last_action >= DecisionAction::FreezeProcess)
            .count() as u32;
        let background_jobs = (active_cases * 2 + critical_cases).min(u8::MAX as u32) as u8;

        let perf_capacity = self.host.performance_lanes.max(1) as f32;
        let eff_capacity = self.host.efficiency_lanes.max(1) as f32;

        let performance_cores = ((critical_cases as f32 * 40.0 + active_cases as f32 * 10.0)
            / perf_capacity)
            .clamp(0.0, 100.0) as u8;
        let efficiency_cores =
            ((background_jobs as f32 * 12.0) / eff_capacity).clamp(0.0, 100.0) as u8;

        let point = TelemetryPoint {
            slot: time_slot(),
            performance_cores,
            efficiency_cores,
            background_jobs,
        };

        if self
            .telemetry_points
            .front()
            .map(|existing| existing.slot == point.slot)
            .unwrap_or(false)
        {
            self.telemetry_points.pop_front();
        }

        self.telemetry_points.push_front(point);
        while self.telemetry_points.len() > MAX_TELEMETRY_POINTS {
            self.telemetry_points.pop_back();
        }
    }
}

impl BehavioralEvent {
    fn provider_id(&self) -> &str {
        match self {
            BehavioralEvent::ExecutionStart { provider_id, .. }
            | BehavioralEvent::ThreadInspection { provider_id, .. }
            | BehavioralEvent::FileMutation { provider_id, .. }
            | BehavioralEvent::NetworkConnection { provider_id, .. }
            | BehavioralEvent::SelfProtectionEvent { provider_id, .. }
            | BehavioralEvent::ModuleIntegrity { provider_id, .. }
            | BehavioralEvent::PrivilegeEscalation { provider_id, .. } => provider_id,
        }
    }

    fn process_id(&self) -> u32 {
        match self {
            BehavioralEvent::ExecutionStart { process_id, .. }
            | BehavioralEvent::ThreadInspection { process_id, .. }
            | BehavioralEvent::FileMutation { process_id, .. }
            | BehavioralEvent::NetworkConnection { process_id, .. }
            | BehavioralEvent::SelfProtectionEvent { process_id, .. }
            | BehavioralEvent::ModuleIntegrity { process_id, .. }
            | BehavioralEvent::PrivilegeEscalation { process_id, .. } => *process_id,
        }
    }

    fn process_name(&self) -> &str {
        match self {
            BehavioralEvent::ExecutionStart { process_name, .. }
            | BehavioralEvent::ThreadInspection { process_name, .. }
            | BehavioralEvent::FileMutation { process_name, .. }
            | BehavioralEvent::NetworkConnection { process_name, .. }
            | BehavioralEvent::SelfProtectionEvent { process_name, .. }
            | BehavioralEvent::ModuleIntegrity { process_name, .. }
            | BehavioralEvent::PrivilegeEscalation { process_name, .. } => process_name,
        }
    }

    fn short_label(&self) -> &'static str {
        match self {
            BehavioralEvent::ExecutionStart { .. } => "execution start",
            BehavioralEvent::ThreadInspection { .. } => "thread inspection",
            BehavioralEvent::FileMutation { .. } => "file mutation",
            BehavioralEvent::NetworkConnection { .. } => "network connection",
            BehavioralEvent::SelfProtectionEvent { .. } => "self-protection event",
            BehavioralEvent::ModuleIntegrity { .. } => "module integrity",
            BehavioralEvent::PrivilegeEscalation { .. } => "privilege escalation",
        }
    }

    fn origin_summary(&self) -> String {
        match self {
            BehavioralEvent::ExecutionStart {
                image_path,
                parent_process,
                ..
            } => format!(
                "Image {} launched by {}",
                image_path,
                parent_process.as_deref().unwrap_or("unknown parent")
            ),
            BehavioralEvent::ThreadInspection {
                target_process,
                origin,
                ..
            } => format!("Thread origin {:?} against {}", origin, target_process),
            BehavioralEvent::FileMutation { path, entropy, .. } => {
                format!("Write activity at {} with entropy {:.2}", path, entropy)
            }
            BehavioralEvent::NetworkConnection {
                remote_address,
                remote_port,
                ..
            } => format!("Outbound connection to {}:{}", remote_address, remote_port),
            BehavioralEvent::SelfProtectionEvent {
                target, technique, ..
            } => {
                format!("Self-protection event {:?} against {}", technique, target)
            }
            BehavioralEvent::ModuleIntegrity { module_name, .. } => {
                format!("Module integrity event for {}", module_name)
            }
            BehavioralEvent::PrivilegeEscalation { target, vector, .. } => {
                format!("Privilege escalation {:?} targeting {}", vector, target)
            }
        }
    }
}

fn action_for_score(score: i32) -> DecisionAction {
    if score >= 80 {
        DecisionAction::EmergencyLockdown
    } else if score >= 60 {
        DecisionAction::FreezeProcess
    } else if score >= 40 {
        DecisionAction::BlockOperation
    } else if score >= 25 {
        DecisionAction::Escalate
    } else {
        DecisionAction::Observe
    }
}

fn severity_for(action: DecisionAction) -> &'static str {
    match action {
        DecisionAction::Observe => "low",
        DecisionAction::Escalate => "medium",
        DecisionAction::BlockOperation => "high",
        DecisionAction::FreezeProcess | DecisionAction::EmergencyLockdown => "critical",
    }
}

fn action_label(action: DecisionAction) -> &'static str {
    match action {
        DecisionAction::Observe => "observe",
        DecisionAction::Escalate => "escalate",
        DecisionAction::BlockOperation => "block operation",
        DecisionAction::FreezeProcess => "freeze process",
        DecisionAction::EmergencyLockdown => "emergency lockdown",
    }
}

fn detect_host_profile() -> HostProfile {
    let logical_cpus = std::thread::available_parallelism()
        .map(|count| count.get() as u16)
        .unwrap_or(1);

    let scheduling_mode = if logical_cpus <= 4 {
        SchedulingMode::Relaxed
    } else if logical_cpus <= 12 {
        SchedulingMode::Balanced
    } else {
        SchedulingMode::HighThroughput
    };

    let efficiency_lanes = match scheduling_mode {
        SchedulingMode::Relaxed => 1,
        SchedulingMode::Balanced => (logical_cpus / 3).max(1),
        SchedulingMode::HighThroughput => (logical_cpus / 4).max(2),
    };
    let performance_lanes = logical_cpus.saturating_sub(efficiency_lanes).max(1);

    HostProfile {
        logical_cpus,
        performance_lanes,
        efficiency_lanes,
        scheduling_mode,
    }
}

fn time_slot() -> String {
    let secs = unix_timestamp_secs();
    let minutes = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    format!("{:02}:{:02}", hours, minutes)
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn global_engine() -> &'static Mutex<CoreVanguardEngine> {
    ENGINE.get_or_init(|| Mutex::new(CoreVanguardEngine::new()))
}

pub fn dashboard_snapshot() -> DashboardSnapshot {
    global_engine()
        .lock()
        .expect("engine lock poisoned")
        .dashboard_snapshot()
}

pub fn apply_provider_heartbeat(heartbeat: ProviderHeartbeat) -> anyhow::Result<DashboardSnapshot> {
    let mut engine = global_engine()
        .lock()
        .map_err(|_| anyhow!("engine lock poisoned"))?;
    engine.apply_provider_heartbeat(heartbeat);
    Ok(engine.dashboard_snapshot())
}

pub fn ingest_behavioral_event(event: BehavioralEvent) -> anyhow::Result<DecisionOutcome> {
    let mut engine = global_engine()
        .lock()
        .map_err(|_| anyhow!("engine lock poisoned"))?;
    Ok(engine.ingest_behavioral_event(event))
}

pub fn configure_vault_key(label: &str) -> anyhow::Result<&'static str> {
    global_engine()
        .lock()
        .map_err(|_| anyhow!("engine lock poisoned"))?
        .configure_vault_key(label)
}

pub fn configure_vault_key_secure(
    label: &str,
    bridge_program: Option<&Path>,
) -> anyhow::Result<String> {
    global_engine()
        .lock()
        .map_err(|_| anyhow!("engine lock poisoned"))?
        .configure_vault_key_secure(label, bridge_program)
}

pub fn apply_provider_heartbeat_json(payload: &str) -> anyhow::Result<DashboardSnapshot> {
    let heartbeat: ProviderHeartbeat = serde_json::from_str(payload)?;
    apply_provider_heartbeat(heartbeat)
}

pub fn ingest_behavioral_event_json(payload: &str) -> anyhow::Result<DecisionOutcome> {
    let event: BehavioralEvent = serde_json::from_str(payload)?;
    ingest_behavioral_event(event)
}

pub fn ingest_behavioral_event_with_enforcement(
    event: BehavioralEvent,
) -> anyhow::Result<IngestEnforcementResult> {
    let decision = ingest_behavioral_event(event)?;
    let enforcement = enforcement::enforce_outcome(&decision)?;
    Ok(IngestEnforcementResult {
        decision,
        enforcement,
    })
}

pub fn ingest_behavioral_event_with_enforcement_json(
    payload: &str,
) -> anyhow::Result<IngestEnforcementResult> {
    let event: BehavioralEvent = serde_json::from_str(payload)?;
    ingest_behavioral_event_with_enforcement(event)
}

pub fn replay_behavioral_events_jsonl(payload: &str) -> anyhow::Result<Vec<DecisionOutcome>> {
    let mut outcomes = Vec::new();
    for line in payload.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcomes.push(ingest_behavioral_event_json(trimmed)?);
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_thread_into_critical_target_triggers_lockdown() {
        let mut engine = CoreVanguardEngine::new();
        let outcome = engine.ingest_behavioral_event(BehavioralEvent::ThreadInspection {
            provider_id: "linux.ebpf_guard".to_string(),
            process_id: 4242,
            process_name: "injector".to_string(),
            target_process: "systemd".to_string(),
            target_critical: true,
            cross_process: true,
            origin: ThreadOrigin::Heap,
        });

        assert_eq!(outcome.action, DecisionAction::EmergencyLockdown);
        assert!(outcome.total_score >= 60);
    }

    #[test]
    fn repeated_entropy_writes_escalate() {
        let mut engine = CoreVanguardEngine::new();

        for index in 0..3 {
            let outcome = engine.ingest_behavioral_event(BehavioralEvent::FileMutation {
                provider_id: "linux.file_gate".to_string(),
                process_id: 5150,
                process_name: "encryptor".to_string(),
                path: format!("/srv/data/file-{}", index),
                bytes_written: 524_288,
                entropy: 7.9,
                protected_path: true,
                canary_file: index == 2,
            });

            if index == 2 {
                assert_eq!(outcome.action, DecisionAction::EmergencyLockdown);
            }
        }
    }

    #[test]
    fn provider_heartbeat_marks_provider_online() {
        let mut engine = CoreVanguardEngine::new();
        engine.apply_provider_heartbeat(ProviderHeartbeat {
            id: "linux.netfilter".to_string(),
            label: "Linux Netfilter Guard".to_string(),
            domain: ProviderDomain::LinuxKernel,
            capabilities: vec![ProviderCapability::NetworkInterception],
            state: ComponentState::Online,
            detail: "Adapter connected.".to_string(),
        });

        let snapshot = engine.dashboard_snapshot();
        assert!(snapshot
            .services
            .iter()
            .any(|service| service.label == "Provider mesh"));
    }
}
