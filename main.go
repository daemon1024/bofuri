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
	var pidns uint32 = 4026533918
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
	var bin [128]byte

	copy(bin[:], "/usr/bin/sleep")
	err = inner.Put(bin, bin)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}
	var bin2 [128]byte
	copy(bin2[:], "/usr/bin/ls")
	err = inner.Put(bin2, bin2)
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
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.AttachLSM(link.LSMOptions{objs.BprmStuff})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var i uint32
	err = objs.bpfMaps.Outer.Lookup(pidns, &i)
	if err != nil {
		log.Fatalf("error looking map: %s", err)
	}
	log.Println(i)

	for range ticker.C {

	}
}
