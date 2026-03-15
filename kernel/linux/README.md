# Linux eBPF

Linux now has two real pieces:

- `bpf/corevanguard.bpf.c` tracks `exec`, `open`, `write`, `kill`, and `ptrace` syscalls through a raw-tracepoint program, maintains per-kind counters, and emits ring-buffer samples.
- `agent/src/linux_provider.rs` performs a host scan from `/proc`, registers Linux provider heartbeats, inspects executable mappings and ptrace state, maps live TCP sockets, and ingests those observations into the engine.

What is still missing is the glue between the in-kernel BPF/ring-buffer stream and the Rust engine, plus fanotify/LSM enforcement for file blocking.
