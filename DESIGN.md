# KubeArmor BPF LSM Integration
 
## High Level Module Changes
| Now | Proposed |
| -------- | -------- |
| ![](https://i.imgur.com/vWeIGez.png)| ![](https://i.imgur.com/2d5V7BD.png)      | 

## Module Design

![](https://i.imgur.com/sS4Md0L.png)

## Map Design

![](https://i.imgur.com/LnE2aWy.png)

### Outer Map details

```c
struct outer_hash {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, X);
  __uint(key_size, sizeof(struct outer_key));    // 2*u32
  __uint(value_size, sizeof(u32));               // Inner Map File Descriptor
  __uint(pinning, LIBBPF_PIN_BY_NAME);           // Created in Userspace, Identified in Kernel Space using pinned name
};
```

- Key
    - Identifier for Containers

```c
struct outer_key {
  u32 pid_ns;
  u32 mnt_ns;
};
```

### Inner Map details
```go
&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,            // Hash Value of Entity
		ValueSize:  8,            // Decision Values
		MaxEntries: 1024,
    }
```
- Value
```c
struct data_t {
  bool owner;        // owner only flag
  bool read;         // read only flag 
  bool dir;          // policy directory flag
  bool recursive;    // directory recursive flag
  bool hint;         // policy directory hint
};
```

## Handling of Events

![](https://i.imgur.com/0Qth7Pl.png)

## Hashing

Files and Source Names can be huge. Worst case both add to 8192 bytes. Which is a very large entity for key. 
So we hash that value to u32 key.
We stored hashed values from userspace and lookup up hashed values from kernel space for decision making.

We plan to use a Jenkins hash algorithm modified for use in ebpf land and matching implementation in user land.

[Based on Event Auditor Implementation](https://github.com/kubearmor/KubeArmor/blob/990a852c88ab580011bde8a72adba33625ffcacd/KubeArmor/BPF/hash.h)

Inspirations
 * https://en.wikipedia.org/wiki/Jenkins_hash_function
 * http://burtleburtle.net/bob/c/lookup3.c
 * https://github.com/tildeleb/hashland/blob/46daf2d89bba924a4269f30949050748548effb1/jenkins/jenkins.go

## Deeper Dive with Examples

1. ![](https://i.imgur.com/B5ohdFb.png)

2. ![](https://i.imgur.com/gw9FOwZ.png)
    But what if it's not a match
    ![](https://i.imgur.com/C0VCKwQ.png)
    We explore how directory matching works in the next example

3. ![](https://i.imgur.com/rdFN8w4.png)
    Notice How we split the directory policy to a sets of hints in the map. This helps in efficient matching of directory paths in Kernel Space.
    
    ![](https://i.imgur.com/yx08RKv.png)
    
    What if we try to access a file in a different directory.
    ![](https://i.imgur.com/fSNc6ph.png)
    Presence of no hint helps break through the iteration hence optimising the process.

### Directory Matching
```c=
#pragma unroll
  for (int i = 0; i < MAX_STRING_SIZE; i++) {
    if (path[i] == '\0')
      break;

    if (path[i] == '/') {
      __builtin_memset(&dir, 0, sizeof(dir));
      bpf_probe_read_str(&dir, i + 2, path);

      fp = jenkins_hash(dir, i + 1, 0);

      struct data_t *val = bpf_map_lookup_elem(inner, &fp);
      if (val) {
        if (val->dir) {
          matched = true;
          goto decisionmaker;
        }
        if (val->hint == 0) { // If we match a non directory entity somehow
          break;
        }
      } else {
        break;
      }
    }
  }
```

## TODO/ToCheck
1. In the prototype code we extract path names to intermediate character arrays, But these add on BPF stack which has a limit of 512 bytes. So need to use Per CPU Arrays to store these values in buffers. [Ref](https://stackoverflow.com/questions/53627094/ebpf-track-values-longer-than-stack-size)
2. List out LSM Hooks to be integrated with
3. Find ways to extract resource and parent resource values in each of these Hooks.
4. ...

## Miscellaneous Notes

- **Path Values**
    
    - We get pathname directly from file,bprm,task structure.
    But AppArmor mentions about path resolution using (dentry, vfsmount) from the file descriptor
    Like [Tracee Code Ref](https://github.com/aquasecurity/tracee/blob/9b77a4c8197e2917edea2a5d617892cf3784eb51/pkg/ebpf/c/tracee.bpf.c#L1922)
    
- **Pattern Matcher**
    - AppArmor has it's own DFA based regular expression matching engine
https://elixir.bootlin.com/linux/latest/source/security/apparmor/match.c
    - Geyslan's ebpf pattern matcher : https://github.com/geyslan/ebpf-pattern/tree/a-story-of-two-maps
- **LSM Hooks**
    - AppArmor LSMs: https://elixir.bootlin.com/linux/latest/source/security/apparmor/lsm.c#L1188
    - SELinux LSMs: https://elixir.bootlin.com/linux/latest/source/security/selinux/hooks.c#L7014
    - Program Exec Ops: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h#L35 
    - Task Ops: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h#L604 
    - File Ops: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h#L507 
    - Inode Ops: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h#L213 
    - Socket Ops: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hooks.h#L842

- **Papers/TechDocs**
    - LSM https://www.kernel.org/doc/ols/2002/ols2002-pages-604-617.pdf
    - AppArmor https://lkml.iu.edu/hypermail/linux/kernel/0706.1/0805/techdoc.pdf
    - SELinux https://www.nsa.gov/portals/75/images/resources/everyone/digital-media-center/publications/research-papers/implementing-selinux-as-linux-security-module-report.pdf
    - BPFBox https://www.cisl.carleton.ca/~will/written/conference/bpfbox-ccsw2020.pdf
    - [Mitigating Attacks on a Supercomputer with KRSI](https://www.sans.org/white-papers/40010/)