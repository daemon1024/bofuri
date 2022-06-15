//go:build linux
// +build linux

package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf test.bpf.c -- -I/usr/include/bpf -O2 -g

const (
	OWNER     uint8 = 0
	READ      uint8 = 1
	DIR       uint8 = 2
	RECURSIVE uint8 = 3
	HINT      uint8 = 4
)

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

	dirtoMap("/home/user1/", inner)
	dirtoMap("/home/user2/", inner)

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

	for range ticker.C {

	}
}

func dirtoMap(p string, m *ebpf.Map) error {
	paths := strings.Split(p, "/")
	var dir [128]byte
	var val [128]byte
	val[DIR] = 1
	copy(dir[:], p)
	err := m.Put(dir, val)
	if err != nil {
		return err
	}

	for i := 1; i < len(paths)-1; i++ {
		var dir [128]byte
		var val [128]byte
		val[HINT] = 1
		var hint string = strings.Join(paths[0:i], "/") + "/"
		fmt.Println(hint, len(hint))
		copy(dir[:], hint)
		err := m.Put(dir, val)
		if err != nil {
			return err
		}
	}
	return nil

}
