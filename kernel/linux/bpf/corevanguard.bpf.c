#include <asm/unistd.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

enum cvg_event_kind {
  CVG_EXEC = 0,
  CVG_OPEN = 1,
  CVG_WRITE = 2,
  CVG_KILL = 3,
  CVG_PTRACE = 4,
};

struct cvg_event {
  __u32 pid;
  __u32 tgid;
  __u32 uid;
  __u32 kind;
  __u64 count;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 5);
  __type(key, __u32);
  __type(value, __u64);
} syscall_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 18);
} syscall_events SEC(".maps");

static __always_inline int track_syscall(struct bpf_raw_tracepoint_args *ctx, __u32 kind) {
  __u64 zero = 0;
  __u64 *counter = bpf_map_lookup_elem(&syscall_counters, &kind);
  __u64 next = 1;
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 uid_gid = bpf_get_current_uid_gid();
  struct cvg_event *event;

  if (counter == 0) {
    bpf_map_update_elem(&syscall_counters, &kind, &zero, BPF_ANY);
    counter = bpf_map_lookup_elem(&syscall_counters, &kind);
  }

  if (counter != 0) {
    next = __sync_fetch_and_add(counter, 1) + 1;
  }

  if (next <= 4 || (next % 128) == 0) {
    event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
    if (event != 0) {
      event->pid = (__u32)pid_tgid;
      event->tgid = (__u32)(pid_tgid >> 32);
      event->uid = (__u32)uid_gid;
      event->kind = kind;
      event->count = next;
      bpf_ringbuf_submit(event, 0);
    }
  }

  return 0;
}

SEC("raw_tracepoint/sys_enter")
int corevanguard_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
  long syscall_id = (long)ctx->args[1];

  switch (syscall_id) {
  case __NR_execve:
#ifdef __NR_execveat
  case __NR_execveat:
#endif
    return track_syscall(ctx, CVG_EXEC);
  case __NR_open:
#ifdef __NR_openat
  case __NR_openat:
#endif
    return track_syscall(ctx, CVG_OPEN);
  case __NR_write:
#ifdef __NR_pwrite64
  case __NR_pwrite64:
#endif
    return track_syscall(ctx, CVG_WRITE);
  case __NR_kill:
#ifdef __NR_tgkill
  case __NR_tgkill:
#endif
    return track_syscall(ctx, CVG_KILL);
#ifdef __NR_ptrace
  case __NR_ptrace:
    return track_syscall(ctx, CVG_PTRACE);
#endif
  default:
    return 0;
  }
}

char LICENSE[] SEC("license") = "GPL";
