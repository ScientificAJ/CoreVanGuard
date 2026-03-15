# macOS Endpoint Security

`CoreVanguardES/main.mm` is now a real Endpoint Security subscriber target. It creates an ES client and subscribes to:

- `ES_EVENT_TYPE_NOTIFY_EXEC`
- `ES_EVENT_TYPE_NOTIFY_OPEN`
- `ES_EVENT_TYPE_NOTIFY_SIGNAL`
- `ES_EVENT_TYPE_NOTIFY_PTRACE`

It still needs the full system-extension packaging, entitlement provisioning, and event transport into the Rust engine.
