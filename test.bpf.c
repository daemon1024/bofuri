// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define EPERM 1
#define ARRAYSIZE 64
#define MAX_STRING_SIZE 128
#define MAX_BUFFER_SIZE 512
#define MAX_BUFFERS 1
#define PATH_BUFFER 0

#define READ_KERN(ptr)                                                         \
  ({                                                                           \
    typeof(ptr) _val;                                                          \
    __builtin_memset(&_val, 0, sizeof(_val));                                  \
    bpf_core_read(&_val, sizeof(_val), &ptr);                                  \
    _val;                                                                      \
  })

struct key_t {
  u8 proc[ARRAYSIZE];
  u8 fs[ARRAYSIZE];
};

struct data_t {
  bool owner;
  bool read;
  bool dir;
  bool recursive;
  bool hint;
};

typedef struct buffers {
  u8 buf[MAX_BUFFER_SIZE];
} bufs_t;

#undef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, bufs_t);
  __uint(max_entries, MAX_BUFFERS);
} bufs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, MAX_BUFFERS);
} bufs_off SEC(".maps");

struct outer_hash {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, 1024);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct outer_hash outer SEC(".maps");

static __always_inline bufs_t *get_buf(int idx) {
  return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
  bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32 *get_buf_off(int buf_idx) {
  return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

static inline struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

// Explained in
// https://github.com/chriskaliX/Hades/blob/1830ee4c19101faaba896186b5e200258bc15860/plugin/driver/eBPF/kernel/include/utils.h#L98
static __always_inline bool prepend_path(struct path *path, bufs_t *string_p) {
  char slash = '/';
  char null = '\0';
  int offset = MAX_STRING_SIZE;

  if (path == NULL || string_p == NULL) {
    return false;
  }

  struct dentry *dentry = path->dentry;
  struct vfsmount *vfsmnt = path->mnt;

  struct mount *mnt = real_mount(vfsmnt);

  struct dentry *parent;
  struct dentry *mnt_root;
  struct mount *m;
  struct qstr d_name;

#pragma unroll
  for (int i = 0; i < 30; i++) {
    parent = BPF_CORE_READ(dentry, d_parent);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    if (dentry == mnt_root) {
      m = BPF_CORE_READ(mnt, mnt_parent);
      if (mnt != m) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt = m;
        continue;
      }
      break;
    }

    if (dentry == parent) {
      break;
    }

    // get d_name
    d_name = BPF_CORE_READ(dentry, d_name);

    offset -= (d_name.len + 1);
    if (offset < 0)
      break;

    int sz = bpf_probe_read_str(
        &(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]),
        (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
    if (sz > 1) {
      bpf_probe_read(
          &(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1,
          &slash);
    } else {
      offset += (d_name.len + 1);
    }

    dentry = parent;
  }

  if (offset == MAX_STRING_SIZE) {
    return false;
  }

  bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
  offset--;

  bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);
  set_buf_off(PATH_BUFFER, offset);
  return true;
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns) {
  struct pid_namespace *pidns = READ_KERN(ns->pid_ns_for_children);
  return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task) {
  return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static struct file *get_task_file(struct task_struct *t) {
  return BPF_CORE_READ(t, mm, exe_file);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_stuff, struct linux_binprm *bprm, int ret) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = get_task_pid_ns_id(t);

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 *inner = bpf_map_lookup_elem(&outer, &pid_ns);

  bpf_printk("%u", pid_ns);
  if (!inner) {
    return 0;
  }
  struct key_t p;
  __builtin_memset(
      &p, 0,
      sizeof(
          p)); // Important to initalise empty, spent a day for this :facepalm:

  // check for whitelist/blacklist posture
  char allow_key[ARRAYSIZE] = "allow";
  char *allow = bpf_map_lookup_elem(inner, &allow_key);

  bpf_probe_read_str(&p.proc, ARRAYSIZE, bprm->filename);

  // look up only path in the map
  struct data_t *val = bpf_map_lookup_elem(inner, &p);
  if (allow) {
    if (!val) {
      bpf_printk("denying %s due to not in allowlist \n", p.proc);
      return -EPERM;
    }
  } else {
    if (val) {
      bpf_printk("denying %s due to in blacklist \n", p.proc);
      return -EPERM;
    }
  }

  // look up path + fromsource in map
  struct task_struct *parent_task = BPF_CORE_READ(t, parent);
  struct file *file_p = get_task_file(parent_task);
  if (file_p == NULL)
    return ret;
  bufs_t *string_buf = get_buf(PATH_BUFFER);
  if (string_buf == NULL)
    return ret;
  struct path f_path = BPF_CORE_READ(file_p, f_path);
  if (!prepend_path(&f_path, string_buf))
    return ret;

  u32 *offset = get_buf_off(PATH_BUFFER);
  if (offset == NULL)
    return ret;

  bpf_probe_read(&p.fs, ARRAYSIZE,
                 &string_buf->buf[*offset & (MAX_STRING_SIZE - 1)]);
  val = bpf_map_lookup_elem(inner, &p);
  if (allow) {
    if (!val) {
      bpf_printk("denying %s with source %s due to not in allowlist \n", p.proc,
                 p.fs);
      return -EPERM;
    }
  } else {
    if (val) {
      bpf_printk("denying %s with source %s due to in blacklist \n", p.proc,
                 p.fs);
      return -EPERM;
    }
  }

  return ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = get_task_pid_ns_id(t);

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 *inner = bpf_map_lookup_elem(&outer, &pid_ns);

  bpf_printk("%u", pid_ns);
  if (!inner) {
    return 0;
  }
  bpf_printk("family %d", address->sa_family);
  bpf_printk("type sock %d, type sock sk %d, protocol %d", sock->type,
             sock->sk->sk_type, sock->sk->sk_protocol);

  struct key_t p;
  __builtin_memset(&p, 0, sizeof(p));

  p.proc[0] = sock->sk->sk_protocol;

  if (bpf_map_lookup_elem(inner, &p)) {
    bpf_printk("denying protocol %d", sock->sk->sk_protocol);
    return -EPERM;
  }
  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restricted_file_open, struct file *file) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = get_task_pid_ns_id(t);

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u32 *inner = bpf_map_lookup_elem(&outer, &pid_ns);

  bpf_printk("%u", pid_ns);
  if (!inner) {
    return 0;
  }
  char path[MAX_STRING_SIZE] = {};
  if (bpf_d_path(&file->f_path, path, MAX_STRING_SIZE) < 0) {
    return 0;
  }
  bpf_printk("file access %s", path);

  char dir[MAX_STRING_SIZE] = {};
  char null = '\0';

#pragma unroll
  for (int i = 0; i < ARRAYSIZE; i++) {
    if (path[i] == '\0')
      break;

    if (path[i] == '/') {
      __builtin_memset(&dir, 0, sizeof(dir));
      bpf_probe_read_str(&dir, i + 2, path);

      struct data_t *val = bpf_map_lookup_elem(inner, &dir);
      bpf_printk("checking sub directory access %s", dir);
      if (val) {
        bpf_printk("got value");
        if (val->dir) {
          bpf_printk("matched");
          return -EPERM;
        }
        if (val->hint == 0) {
          break;
        }
        bpf_printk("hint true");
      } else {
        break;
      }
    }
  }

  return 0;
}
