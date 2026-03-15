#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

struct cvg_event {
  unsigned int pid;
  unsigned int tgid;
  unsigned int uid;
  unsigned int kind;
  unsigned long long count;
};

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int signal_number) {
  (void)signal_number;
  exiting = 1;
}

static int handle_ringbuf_event(void *ctx, void *data, size_t data_sz) {
  const struct cvg_event *event = data;

  (void)ctx;

  if (data_sz < sizeof(*event)) {
    return 0;
  }

  printf(
      "{\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"kind\":%u,\"count\":%llu}\n",
      event->pid, event->tgid, event->uid, event->kind,
      (unsigned long long)event->count);
  fflush(stdout);
  return 0;
}

int main(int argc, char **argv) {
  const char *object_path = argc > 1 ? argv[1] : "kernel/linux/out/corevanguard.bpf.o";
  struct bpf_object *object = NULL;
  struct bpf_program *program = NULL;
  struct bpf_link *link = NULL;
  struct ring_buffer *ring_buffer = NULL;
  struct rlimit memlock = {RLIM_INFINITY, RLIM_INFINITY};
  int ring_buffer_fd;
  int result = 1;

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  if (setrlimit(RLIMIT_MEMLOCK, &memlock) != 0) {
    perror("setrlimit");
    return 1;
  }

  object = bpf_object__open_file(object_path, NULL);
  if (libbpf_get_error(object)) {
    fprintf(stderr, "failed to open BPF object: %s\n", object_path);
    return 1;
  }

  if (bpf_object__load(object) != 0) {
    fprintf(stderr, "failed to load BPF object\n");
    goto cleanup;
  }

  program = bpf_object__find_program_by_name(object, "corevanguard_sys_enter");
  if (program == NULL) {
    fprintf(stderr, "failed to find corevanguard_sys_enter program\n");
    goto cleanup;
  }

  link = bpf_program__attach_raw_tracepoint(program, "sys_enter");
  if (libbpf_get_error(link)) {
    fprintf(stderr, "failed to attach raw tracepoint\n");
    link = NULL;
    goto cleanup;
  }

  ring_buffer_fd = bpf_object__find_map_fd_by_name(object, "syscall_events");
  if (ring_buffer_fd < 0) {
    fprintf(stderr, "failed to find syscall_events map\n");
    goto cleanup;
  }

  ring_buffer =
      ring_buffer__new(ring_buffer_fd, handle_ringbuf_event, NULL, NULL);
  if (ring_buffer == NULL) {
    fprintf(stderr, "failed to create ring buffer\n");
    goto cleanup;
  }

  while (!exiting) {
    ring_buffer__poll(ring_buffer, 250);
  }

  result = 0;

cleanup:
  ring_buffer__free(ring_buffer);
  bpf_link__destroy(link);
  bpf_object__close(object);
  return result;
}
