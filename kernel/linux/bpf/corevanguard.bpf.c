#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} event_counter SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int corevanguard_exec_watch(struct bpf_raw_tracepoint_args *ctx) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&event_counter, &key);

  if (value != 0) {
    __sync_fetch_and_add(value, 1);
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";

