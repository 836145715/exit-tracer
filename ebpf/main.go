//go:build linux

// Generic eBPF exit/signal event collector. Emits raw JSONL on stdout.
// Has no AI, VM heuristics, process injection, ptrace, or target modification.
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed exit_bpfel.o
var programObject []byte

type kernelEvent struct {
	TimestampNS uint64
	ActorTGID   uint32
	ActorTID    uint32
	TargetTID   uint32
	Kind        uint32
	Signal      uint32
	Code        int32
	StackID     int32
	Comm        [16]byte
	SyscallNR   uint32
	Arg0        uint64
	Arg1        uint64
	Arg2        uint64
}

func procThreads(packageName string, tidMap *ebpf.Map, known map[uint32]uint32) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	found := make(map[uint32]uint32, len(known))
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid < 1 {
			continue
		}
		cmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		p := strings.SplitN(string(cmd), "\x00", 2)[0]
		if p != packageName && !strings.HasPrefix(p, packageName+":") {
			continue
		}
		tids, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			continue
		}
		for _, td := range tids {
			n, err := strconv.Atoi(td.Name())
			if err != nil || n < 1 {
				continue
			}
			found[uint32(n)] = uint32(pid)
		}
	}
	for tid, tgid := range found {
		if known[tid] == tgid {
			continue
		}
		if err := tidMap.Put(tid, tgid); err == nil {
			known[tid] = tgid
		}
	}
	for tid := range known {
		if _, ok := found[tid]; !ok {
			_ = tidMap.Delete(tid)
			delete(known, tid)
		}
	}
}

func main() {
	pkg := flag.String("package", "", "optional package to filter in the kernel")
	ready := flag.String("ready-file", "", "create when programs are successfully attached and reader initialized")
	flag.Parse()
	if err := run(*pkg, *ready); err != nil {
		fmt.Fprintln(os.Stderr, "ebpf startup/runtime error:", err)
		os.Exit(1)
	}
}

func run(pkg, readyFile string) error {
	// Modern kernels account BPF memory differently, so errors are non-fatal.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "rlimit note:", err)
	}
	objSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programObject))
	if err != nil {
		return fmt.Errorf("parse BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(objSpec)
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}
	defer coll.Close()
	cfg := coll.Maps["config"]
	threads := coll.Maps["target_tids"]
	stacks := coll.Maps["stacks"]
	events := coll.Maps["events"]
	if cfg == nil || threads == nil || stacks == nil || events == nil {
		return errors.New("missing expected BPF map")
	}
	var mode uint32
	if pkg != "" {
		mode = 1
	}
	var key uint32
	if err := cfg.Put(key, mode); err != nil {
		return fmt.Errorf("configure filter: %w", err)
	}
	known := map[uint32]uint32{}
	if pkg != "" {
		procThreads(pkg, threads, known)
	}

	wanted := []struct{ group, event, prog string }{
		{"sched", "sched_process_exit", "on_exit"},
		{"signal", "signal_generate", "on_signal_generate"},
		{"signal", "signal_deliver", "on_signal_deliver"},
		{"raw_syscalls", "sys_enter", "on_raw_sys_enter"},
	}
	links := make([]link.Link, 0, len(wanted))
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, what := range wanted {
		prog := coll.Programs[what.prog]
		if prog == nil {
			return fmt.Errorf("program %s missing", what.prog)
		}
		l, err := link.Tracepoint(what.group, what.event, prog, nil)
		if err != nil {
			if what.group == "raw_syscalls" {
				fmt.Fprintf(os.Stderr, "optional raw syscall tracepoint unavailable: %v\n", err)
				continue
			}
			return fmt.Errorf("attach %s/%s: %w", what.group, what.event, err)
		}
		links = append(links, l)
	}
	rd, err := perf.NewReader(events, os.Getpagesize()*8)
	if err != nil {
		return fmt.Errorf("open perf reader: %w", err)
	}
	defer rd.Close()
	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte("ready\n"), 0644); err != nil {
			return err
		}
		defer os.Remove(readyFile)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() { <-sigs; cancel(); _ = rd.Close() }()
	if pkg != "" {
		go func() {
			t := time.NewTicker(500 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					procThreads(pkg, threads, known)
				}
			}
		}()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			fmt.Fprintln(os.Stderr, "perf read:", err)
			continue
		}
		if record.LostSamples != 0 {
			_ = enc.Encode(map[string]any{"type": "lost_samples", "count": record.LostSamples, "observed_at": time.Now().Format(time.RFC3339Nano)})
			continue
		}
		var evt kernelEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			fmt.Fprintln(os.Stderr, "decode event:", err)
			continue
		}
		labels := map[uint32]string{1: "sched_process_exit", 2: "signal_generate", 3: "signal_deliver", 4: "sys_enter"}
		name := strings.TrimRight(string(evt.Comm[:]), "\x00")
		entry := map[string]any{
			"type": labels[evt.Kind], "mono_ns": evt.TimestampNS,
			"observed_at": time.Now().Format(time.RFC3339Nano),
			"tgid":        evt.ActorTGID, "tid": evt.ActorTID, "target_tid": evt.TargetTID,
			"signal": evt.Signal, "code": evt.Code, "comm": name,
			"user_stack_id": evt.StackID,
		}
		if evt.Kind == 4 {
			entry["syscall_nr"] = evt.SyscallNR
			entry["args"] = []string{
				fmt.Sprintf("0x%x", evt.Arg0),
				fmt.Sprintf("0x%x", evt.Arg1),
				fmt.Sprintf("0x%x", evt.Arg2),
			}
		}
		if evt.StackID >= 0 {
			var ips [32]uint64
			stackKey := uint32(evt.StackID)
			if err := stacks.Lookup(stackKey, &ips); err == nil {
				stack := []string{}
				for _, pc := range ips {
					if pc == 0 {
						break
					}
					stack = append(stack, fmt.Sprintf("0x%x", pc))
				}
				entry["user_stack_pc"] = stack
			} else {
				entry["stack_lookup_error"] = err.Error()
			}
		}
		if err := enc.Encode(entry); err != nil {
			return err
		}
	}
}

// keep embed import tied to build-time image.
var _ embed.FS
var _ = filepath.Separator
