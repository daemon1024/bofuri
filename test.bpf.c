// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 1
#define ARRAYSIZE 128

#define READ_KERN(ptr)                                                         \
  ({                                                                           \
    typeof(ptr) _val;                                                          \
    __builtin_memset(&_val, 0, sizeof(_val));                                  \
    bpf_core_read(&_val, sizeof(_val), &ptr);                                  \
    _val;                                                                      \
  })

struct data_t {
  char fs[ARRAYSIZE];
  // bool readonl
};

struct inner_array {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, int);
  __type(value, struct data_t);
} inner_array SEC(".maps");

struct outer_hash {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 1024);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  // __array(values, struct inner_array);
} outer SEC(".maps");

static bool isequal(const char *a, const char *b) {
#pragma unroll
  for (int i = 0; i < ARRAYSIZE; i++) {
    if (a[i] == '\0' && b[i] == '\0')
      break;

    if (a[i] != b[i])
      return false;
  }
  return true;
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns) {
  struct pid_namespace *pidns = READ_KERN(ns->pid_ns_for_children);
  return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline struct data_t do_reg_inline_lookup(void *inner_map,
                                                          int key) {
  struct data_t *result;

  result = bpf_map_lookup_elem(inner_map, &key);
  return *result;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_stuff, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = get_task_pid_ns_id(t);

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  struct inner_array *inner;
  inner = bpf_map_lookup_elem(&outer, &pid_ns);

  bpf_printk("%u", pid_ns);
  if (!inner) {
    return 0;
  }

  char filename[ARRAYSIZE];
  // ad whitelist map
  bpf_probe_read_str(&filename, 128, bprm->filename);
  bpf_printk("%s", filename);
  u32 k = 0;
#pragma unroll
  for (u32 i = 0; i < sizeof(*inner); i++) {
    // need to use an intermiate variable to hold the value since the pointer
    // will not increment correctly.
    k = i;
    char *key = bpf_map_lookup_elem(inner, &k);
    if (key) {
      bpf_printk("%s %d\n", key,k);
      bool comp = isequal(filename, key);
      if (comp)
        return -EPERM;
    }
  }

  return ret;
}
