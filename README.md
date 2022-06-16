# Bofuri

Prototypical Runtime Security Enforcement Tool

## Requirements

- Kernel >5.8
- Have BPF,BPF-LSM, BTF enabled in kernel
- go
- libbpf-dev clang llvm libelf-dev
## Setup

```
git clone https://github.com/daemon1024/bofuri
cd bofuri

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

go mod tidy
go generate
sudo -E go run ./...
```

## [Design](./DESIGN.md)
---

### Bofuri??

*I Don't Want to Get Hurt, So I'll Max Out My Defense*

An anime character where a player designing a character for a RPG gives up all other skills for the sake of being nearly invulnerable, becoming a formidable defender in combat.



