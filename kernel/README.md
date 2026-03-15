# Kernel Surface

Each OS target stays isolated so the interception logic can evolve with the native toolchain and signing model it actually needs.

- `windows/`: WDF / KMDF MiniFilter driver workspace
- `linux/`: eBPF / LSM probes and helpers
- `macos/`: Endpoint Security client and future system extension target

