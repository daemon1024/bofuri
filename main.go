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

	log.Printf("Checking hash sl %d", JHash([]byte("/bin/sleep"), 0))
	log.Printf("Checking hash procfs %d", JHash(append([]byte("/bin/sleep"), []byte("/bin/bash")...), 0))
	log.Printf("Checking hash bh %d", JHash([]byte("/bin/bash"), 0))
	log.Printf("Checking hash proc+fs %d", JHash([]byte("/bin/sleep"), 0)+JHash([]byte("/bin/bash"), 0))

	log.Println("Waiting for events..")
	var pidns uint32 = 4026533271
	var mntns uint32 = 4026533265
	innerspec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1024,
	}
	inner, err := ebpf.NewMap(innerspec)
	if err != nil {
		log.Fatalf("error creating inner map: %s", err)
	}
	defer inner.Close()

	var allow [8]byte
	copy(allow[:], "allow")

	// err = inner.Put(allow, allow)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}

	var bin [128]byte
	copy(bin[:], "/bin/sleep")
	log.Printf("Checking hash %d %d", JHash(bin[:], 0), len(bin))
	copy(bin[64:128], "/bin/bash")
	err = inner.Put(JHash([]byte("/bin/sleep"), 0)+JHash([]byte("/bin/bash"), 0), allow)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}
	var bin2 [128]byte
	copy(bin2[:], "/bin/ls")
	err = inner.Put(JHash([]byte("/bin/ls"), 0), allow)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}
	var net [4]byte
	net[0] = 17
	err = inner.Put(net, allow)
	if err != nil {
		log.Fatalf("error updating map: %s", err)
	}

	dirtoMap("/home/user1/", inner)
	dirtoMap("/home/user2/", inner)

	var s []byte
	err = inner.Lookup(JHash([]byte("/bin/ls"), 0), &s)
	if err != nil {
		log.Fatalf("error looking map: %s", err)
	}
	log.Println("testing lookup", string(s), inner.FD())

	outer, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    8,
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

	err = outer.Put([]uint32{pidns, mntns}, inner)
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
	err = objs.bpfMaps.Outer.Lookup([]uint32{pidns, mntns}, &i)
	if err != nil {
		log.Fatalf("error looking map: %s", err)
	}
	log.Println(i)

	for range ticker.C {

	}
}

func dirtoMap(p string, m *ebpf.Map) error {
	paths := strings.Split(p, "/")
	var val [8]byte
	val[DIR] = 1
	err := m.Put(JHash([]byte(p), 0), val)
	if err != nil {
		return err
	}

	for i := 1; i < len(paths)-1; i++ {
		var val [8]byte
		val[HINT] = 1
		var hint string = strings.Join(paths[0:i], "/") + "/"
		fmt.Println(hint, len(hint))
		err := m.Put(JHash([]byte(hint), 0), val)
		if err != nil {
			return err
		}
	}
	return nil

}
