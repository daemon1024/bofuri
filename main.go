//go:build linux
// +build linux

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf test.bpf.c -- -I/usr/include/bpf -O2 -g

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	log.Println("Waiting for events..")
	var pidns uint32 = 4026533271
	innerspec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    128,
		ValueSize:  128,
		MaxEntries: 1024,
	}
	inner, err := ebpf.NewMap(innerspec)
	if err != nil {
		log.Fatalf("error creating inner map: %s", err)
	}
	defer inner.Close()

	innerspec2 := &ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  128,
		MaxEntries: 5,
	}
	inner2, err := ebpf.NewMap(innerspec2)
	if err != nil {
		log.Fatalf("error creating inner map: %s", err)
	}
	defer inner2.Close()

	var allow [128]byte
	copy(allow[:], "allow")

	// err = inner.Put(allow, allow)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}

	var bin [128]byte
	copy(bin[:], "/bin/sleep")
	copy(bin[64:128], "/bin/bash")
	err = inner.Put(bin, bin)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}
	var bin2 [128]byte
	copy(bin2[:], "/bin/ls")
	err = inner.Put(bin2, bin2)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}
	var net [128]byte
	net[0] = 17
	err = inner.Put(net, net)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}

	var dir [128]byte
	copy(dir[:], "/home/user1")
	err = inner2.Put(uint32(0), dir)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}

	var dir2 [128]byte
	copy(dir2[:], "/home/user2")
	err = inner2.Put(uint32(1), dir2)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}

	var s []byte
	err = inner.Lookup(bin, &s)
	if err != nil {
		log.Fatalf("error looking map: %s", err)
	}
	log.Println("testing lookup", string(s), inner.FD())

	outer, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
		Pinning:    ebpf.PinByName,
		InnerMap:   innerspec,
		Name:       "outer",
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf",
	})
	if err != nil {
		log.Fatalf("error creating outer map: %s", err)
	}
	defer outer.Unpin()
	defer outer.Close()

	err = outer.Put(pidns, inner)
	if err != nil {
		log.Fatalf("error updating outer map: %s", err)
	}

	outer2, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
		Pinning:    ebpf.PinByName,
		InnerMap:   innerspec2,
		Name:       "outer2",
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf",
	})
	if err != nil {
		log.Fatalf("error creating outer map: %s", err)
	}
	defer outer2.Unpin()
	defer outer2.Close()

	err = outer2.Put(pidns, inner2)
	if err != nil {
		log.Fatalf("error updating outer2 map: %s", err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpbprm, err := link.AttachLSM(link.LSMOptions{objs.BprmStuff})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpbprm.Close()

	kpsc, err := link.AttachLSM(link.LSMOptions{objs.SocketConnect})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpsc.Close()

	kpfo, err := link.AttachLSM(link.LSMOptions{objs.RestrictedFileOpen})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpfo.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var i uint32
	err = objs.bpfMaps.Outer.Lookup(pidns, &i)
	if err != nil {
		log.Fatalf("error looking map: %s", err)
	}
	log.Println(i)

	err = objs.bpfMaps.Outer2.Lookup(pidns, &i)
	if err != nil {
		log.Fatalf("error looking map: %s", err)
	}
	log.Println(i)

	for range ticker.C {

	}
}
