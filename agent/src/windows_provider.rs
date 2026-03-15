use crate::{DashboardSnapshot, DecisionOutcome};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsBridgeReport {
    pub events_observed: usize,
    pub decisions: Vec<DecisionOutcome>,
    pub snapshot: DashboardSnapshot,
}

#[cfg(not(target_os = "windows"))]
pub fn run_minifilter_bridge(_max_events: usize) -> Result<WindowsBridgeReport> {
    bail!("MiniFilter bridge is only available on Windows")
}

#[cfg(target_os = "windows")]
pub fn run_minifilter_bridge(max_events: usize) -> Result<WindowsBridgeReport> {
    imp::run_minifilter_bridge(max_events)
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use crate::{
        apply_provider_heartbeat, ingest_behavioral_event, BehavioralEvent, ComponentState,
        ProviderCapability, ProviderDomain, ProviderHeartbeat,
    };
    use std::ffi::c_void;
    use std::iter;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};

    type Handle = *mut c_void;
    type HResult = i32;
    type Dword = u32;

    const S_OK: HResult = 0;

    #[repr(C)]
    struct FilterMessageHeader {
        reply_length: Dword,
        message_id: u64,
    }

    #[repr(C)]
    struct DriverTelemetryMessage {
        process_id: u32,
        major_function: u32,
        write_intent: u8,
        blocked: u8,
        reserved: [u8; 2],
        path: [u16; 260],
    }

    #[repr(C)]
    struct DriverMessageEnvelope {
        header: FilterMessageHeader,
        payload: DriverTelemetryMessage,
    }

    #[link(name = "fltlib")]
    extern "system" {
        fn FilterConnectCommunicationPort(
            lpPortName: *const u16,
            dwOptions: Dword,
            lpContext: *const c_void,
            wSizeOfContext: u16,
            lpSecurityAttributes: *const c_void,
            hPort: *mut Handle,
        ) -> HResult;

        fn FilterGetMessage(
            hPort: Handle,
            lpMessageBuffer: *mut FilterMessageHeader,
            dwMessageBufferSize: Dword,
            lpOverlapped: *mut c_void,
        ) -> HResult;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CloseHandle(hObject: Handle) -> i32;
    }

    pub fn run_minifilter_bridge(max_events: usize) -> Result<WindowsBridgeReport> {
        let _ = apply_provider_heartbeat(ProviderHeartbeat {
            id: "windows.minifilter".to_string(),
            label: "Windows MiniFilter".to_string(),
            domain: ProviderDomain::WindowsKernel,
            capabilities: vec![ProviderCapability::FileInterception],
            state: ComponentState::Online,
            detail: "MiniFilter communication port is connected.".to_string(),
        })?;

        let mut handle: Handle = null_mut();
        let port_name: Vec<u16> = "\\CoreVanguardPort"
            .encode_utf16()
            .chain(iter::once(0))
            .collect();

        let result = unsafe {
            FilterConnectCommunicationPort(port_name.as_ptr(), 0, null(), 0, null(), &mut handle)
        };
        if result != S_OK {
            bail!(
                "failed to connect to MiniFilter port: HRESULT {:#x}",
                result
            );
        }

        let mut decisions = Vec::new();
        let mut events_observed = 0usize;

        while max_events == 0 || events_observed < max_events {
            let mut envelope = DriverMessageEnvelope {
                header: FilterMessageHeader {
                    reply_length: 0,
                    message_id: 0,
                },
                payload: DriverTelemetryMessage {
                    process_id: 0,
                    major_function: 0,
                    write_intent: 0,
                    blocked: 0,
                    reserved: [0; 2],
                    path: [0; 260],
                },
            };

            let status = unsafe {
                FilterGetMessage(
                    handle,
                    &mut envelope.header,
                    size_of::<DriverMessageEnvelope>() as u32,
                    null_mut(),
                )
            };
            if status != S_OK {
                break;
            }

            decisions.push(ingest_behavioral_event(translate_message(
                &envelope.payload,
            ))?);
            events_observed += 1;
        }

        unsafe {
            CloseHandle(handle);
        }

        Ok(WindowsBridgeReport {
            events_observed,
            decisions,
            snapshot: crate::dashboard_snapshot(),
        })
    }

    fn translate_message(message: &DriverTelemetryMessage) -> BehavioralEvent {
        let path = wide_to_string(&message.path);
        BehavioralEvent::FileMutation {
            provider_id: "windows.minifilter".to_string(),
            process_id: message.process_id,
            process_name: format!("pid-{}", message.process_id),
            path: path.clone(),
            bytes_written: if message.write_intent != 0 { 4096 } else { 0 },
            entropy: 0.0,
            protected_path: message.blocked != 0,
            canary_file: path.contains("CoreVanguardCanary"),
        }
    }

    fn wide_to_string(buffer: &[u16]) -> String {
        let end = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
    }
}
