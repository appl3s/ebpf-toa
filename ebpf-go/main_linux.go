package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../bpf_tcp_option_kern.c

func main() {

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("RemoveMemlock failed:", err)
	}

	o := bpfObjects{}
	if err := loadBpfObjects(&o, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer o.Close()

	pa, err := findCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    pa,
		Program: o.bpfPrograms.BpfSockopsToa,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Printf("eBPF program loaded and attached on cgroup %s\n", pa)

	// Wait
	<-stopper
}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, nil
}
