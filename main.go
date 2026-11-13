package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultBase = "/data/local/tmp/exit-tracer"
const traceRoot = "/sys/kernel/tracing"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	action := os.Args[1]
	flags := flag.NewFlagSet(action, flag.ExitOnError)
	pkg := flags.String("package", "", "optional app package to snapshot (/proc)")
	duration := flags.Duration("duration", 0, "recording time (0 = until stop); e.g. 90s")
	base := flags.String("base", defaultBase, "log directory")
	flags.Parse(os.Args[2:])
	switch action {
	case "start":
		if err := start(*pkg, *duration, *base); err != nil {
			fatal(err)
		}
	case "run":
		if err := run(*pkg, *duration, *base); err != nil {
			fatal(err)
		}
	case "stop":
		if err := stop(*base); err != nil {
			fatal(err)
		}
	case "status":
		status(*base)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("Exit Tracer V2 (eBPF preferred, tracefs fallback + logcat)")
	fmt.Println("  exit-tracer start [-package com.example.app] [-duration 90s]")
	fmt.Println("  exit-tracer stop | status")
	fmt.Println("  exit-tracer run [-package ...] [-duration 90s]   # foreground")
	fmt.Println("  Logs: /data/local/tmp/exit-tracer/runs/<timestamp>/")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
func read(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}
func write(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}
func pidFile(base string) string { return filepath.Join(base, "daemon.pid") }
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
func existingPID(base string) int {
	pid, _ := strconv.Atoi(read(pidFile(base)))
	if alive(pid) {
		return pid
	}
	return 0
}
func status(base string) {
	if pid := existingPID(base); pid != 0 {
		fmt.Printf("running pid=%d\n", pid)
	} else {
		fmt.Println("stopped")
	}
	fmt.Println("latest:", read(filepath.Join(base, "latest.txt")))
}
func start(pkg string, duration time.Duration, base string) error {
	if existingPID(base) != 0 {
		return errors.New("already running")
	}
	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(base, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(executable, "run", "-package", pkg, "-duration", duration.String(), "-base", base)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	child := cmd.Process.Pid
	_ = cmd.Process.Release()
	for i := 0; i < 25; i++ {
		if existingPID(base) == child {
			fmt.Printf("started pid=%d\nlogdir=%s\n", child, read(filepath.Join(base, "latest.txt")))
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("start not confirmed; check %s", filepath.Join(base, "daemon.log"))
}
func stop(base string) error {
	pid := existingPID(base)
	if pid == 0 {
		return errors.New("not running")
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	fmt.Printf("sent SIGTERM to tracer pid=%d\n", pid)
	return nil
}

type rotatingWriter struct {
	mu          sync.Mutex
	dir, prefix string
	file        *os.File
	index       int
	bytes       int64
	maxBytes    int64
	maxFiles    int
}

func newRotatingWriter(dir, prefix string, maxBytes int64, maxFiles int) *rotatingWriter {
	return &rotatingWriter{dir: dir, prefix: prefix, maxBytes: maxBytes, maxFiles: maxFiles}
}
func (w *rotatingWriter) rotate() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	name := filepath.Join(w.dir, fmt.Sprintf("%s.%04d.log", w.prefix, w.index))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	w.file = f
	w.bytes = 0
	w.index++
	if w.index > w.maxFiles {
		old := filepath.Join(w.dir, fmt.Sprintf("%s.%04d.log", w.prefix, w.index-w.maxFiles-1))
		_ = os.Remove(old)
	}
	return nil
}
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := 0
	for len(p) > 0 {
		if w.file == nil || w.bytes >= w.maxBytes {
			if err := w.rotate(); err != nil {
				return total, err
			}
		}
		remaining := int(w.maxBytes - w.bytes)
		n := len(p)
		if n > remaining {
			n = remaining
		}
		wrote, err := w.file.Write(p[:n])
		total += wrote
		w.bytes += int64(wrote)
		p = p[wrote:]
		if err != nil {
			return total, err
		}
		if wrote == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (w *rotatingWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
}

func logLine(log *os.File, format string, args ...any) {
	fmt.Fprintf(log, "%s %s\n", time.Now().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
}
func run(pkg string, duration time.Duration, base string) error {
	if os.Geteuid() != 0 {
		return errors.New("root required for tracefs and tombstones")
	}
	if err := os.MkdirAll(filepath.Join(base, "runs"), 0755); err != nil {
		return err
	}
	started := time.Now()
	runDir := filepath.Join(base, "runs", started.Format("20060102-150405")+"-"+strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(runDir, "collector.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer lf.Close()
	logLine(lf, "start: pid=%d package=%q duration=%s", os.Getpid(), pkg, duration)
	if err := write(pidFile(base), strconv.Itoa(os.Getpid())); err != nil {
		return err
	}
	defer func() {
		if existingPID(base) == os.Getpid() {
			_ = os.Remove(pidFile(base))
		}
	}()
	_ = write(filepath.Join(base, "latest.txt"), runDir)
	u, _ := exec.Command("uname", "-a").Output()
	metadata := map[string]any{
		"start_wall": started.Format(time.RFC3339Nano), "start_unix_ms": started.UnixMilli(),
		"package": pkg, "tracer_pid": os.Getpid(), "kernel": strings.TrimSpace(string(u)),
		"tracefs_root": traceRoot, "notes": "Raw events only; no AI or VM classification. eBPF user stack collection is best-effort.",
	}
	saveJSON(filepath.Join(runDir, "metadata.json"), metadata)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	onSignal := make(chan os.Signal, 1)
	signal.Notify(onSignal, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(onSignal)

	type worker struct {
		name     string
		cmd      *exec.Cmd
		finished chan struct{}
		writer   *rotatingWriter
	}
	workers := []worker{}
	launch := func(name string, cmd *exec.Cmd, prefix string, maxMB int64, maxFiles int) {
		r := newRotatingWriter(runDir, prefix, maxMB*1024*1024, maxFiles)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			logLine(lf, "%s: pipe failed: %v", name, err)
			return
		}
		stderrFile, _ := os.OpenFile(filepath.Join(runDir, name+".stderr.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if stderrFile != nil {
			cmd.Stderr = stderrFile
		}
		if err := cmd.Start(); err != nil {
			logLine(lf, "%s: launch failed: %v", name, err)
			if stderrFile != nil {
				_ = stderrFile.Close()
			}
			r.Close()
			return
		}
		finished := make(chan struct{})
		workers = append(workers, worker{name, cmd, finished, r})
		go func() {
			_, copyErr := io.Copy(r, stdout)
			if copyErr != nil {
				logLine(lf, "%s: copy: %v", name, copyErr)
			}
			close(finished)
		}()
		logLine(lf, "%s: started pid=%d", name, cmd.Process.Pid)
	}

	// Prefer the independently loaded eBPF collector. If it does not signal
	// readiness, retain V1 tracefs behavior without touching global tracing.
	ebpfReady := false
	readyFile := filepath.Join(runDir, "ebpf.ready")
	ebpfBinary := filepath.Join(base, "exit-tracer-ebpf")
	if _, err := os.Stat(ebpfBinary); err == nil {
		ebpfCmd := exec.Command(ebpfBinary, "-package", pkg, "-ready-file", readyFile)
		launch("ebpf", ebpfCmd, "ebpf", 16, 16)
		for i := 0; i < 30; i++ {
			if _, err := os.Stat(readyFile); err == nil {
				ebpfReady = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ebpfReady {
			if ebpfCmd.Process != nil {
				_ = ebpfCmd.Process.Kill()
			}
			logLine(lf, "eBPF unavailable or startup timed out; using tracefs fallback; see ebpf.stderr.log")
		}
	} else {
		logLine(lf, "eBPF helper not found: %s; using tracefs fallback", ebpfBinary)
	}
	if ebpfReady {
		metadata["backend"] = "ebpf"
		metadata["ebpf_raw_log"] = "ebpf.XXXX.log"
		metadata["stack_notes"] = "user_stack_pc best-effort; negative user_stack_id is the kernel helper error code"
	} else {
		metadata["backend"] = "tracefs_fallback"
	}
	saveJSON(filepath.Join(runDir, "metadata.json"), metadata)
	instance := filepath.Join(traceRoot, "instances", fmt.Sprintf("exittracer_%d", os.Getpid()))
	instanceCreated := false
	if ebpfReady {
		logLine(lf, "eBPF ready, skipping tracefs fallback")
	} else if err := os.Mkdir(instance, 0755); err != nil {
		logLine(lf, "tracefs unavailable: %v; continuing with logcat", err)
	} else {
		instanceCreated = true
		_ = write(filepath.Join(instance, "tracing_on"), "0")
		_ = write(filepath.Join(instance, "buffer_size_kb"), "2048")
		available := []string{}
		wanted := []string{"sched/sched_process_exit", "signal/signal_generate", "signal/signal_deliver"}
		for _, ev := range wanted {
			eventDir := filepath.Join(instance, "events", ev)
			if _, err := os.Stat(eventDir); err != nil {
				logLine(lf, "event unavailable: %s", ev)
				continue
			}
			if strings.HasPrefix(ev, "signal/") {
				filter := "sig == 4 || sig == 5 || sig == 6 || sig == 7 || sig == 8 || sig == 9 || sig == 11 || sig == 15"
				if err := write(filepath.Join(eventDir, "filter"), filter); err != nil {
					logLine(lf, "cannot apply %s filter: %v", ev, err)
				}
			}
			if err := write(filepath.Join(eventDir, "enable"), "1"); err != nil {
				logLine(lf, "enable %s failed: %v", ev, err)
				continue
			}
			available = append(available, ev)
			if fmtFile, err := os.ReadFile(filepath.Join(eventDir, "format")); err == nil {
				_ = os.WriteFile(filepath.Join(runDir, strings.ReplaceAll(ev, "/", "_")+".format"), fmtFile, 0644)
			}
		}
		metadata["enabled_tracepoints"] = available
		metadata["trace_clock"] = read(filepath.Join(instance, "trace_clock"))
		saveJSON(filepath.Join(runDir, "metadata.json"), metadata)
		if len(available) > 0 {
			if err := write(filepath.Join(instance, "tracing_on"), "1"); err != nil {
				logLine(lf, "enable tracing failed: %v", err)
			} else {
				launch("trace", exec.Command("/system/bin/cat", filepath.Join(instance, "trace_pipe")), "trace", 16, 16)
			}
		}
	}
	launch("logcat", exec.Command("/system/bin/logcat", "-v", "epoch", "-b", "main", "-b", "system", "-b", "crash", "-b", "events", "-T", "1"), "logcat", 16, 8)

	if pkg != "" {
		go scanProcesses(ctx, pkg, runDir, lf)
	}
	if duration > 0 {
		timer := time.NewTimer(duration)
		select {
		case <-timer.C:
			logLine(lf, "duration elapsed")
		case s := <-onSignal:
			logLine(lf, "received %v", s)
		}
		timer.Stop()
	} else {
		s := <-onSignal
		logLine(lf, "received %v", s)
	}
	cancel()
	if instanceCreated {
		_ = write(filepath.Join(instance, "tracing_on"), "0")
	}
	for _, w := range workers {
		_ = w.cmd.Process.Kill()
		_ = w.cmd.Wait()
		select {
		case <-w.finished:
		case <-time.After(1 * time.Second):
			logLine(lf, "timed out draining %s", w.name)
		}
		w.writer.Close()
		logLine(lf, "%s stopped", w.name)
	}
	if instanceCreated {
		for _, ev := range []string{"sched/sched_process_exit", "signal/signal_generate", "signal/signal_deliver"} {
			if _, err := os.Stat(filepath.Join(instance, "events", ev, "enable")); err == nil {
				_ = write(filepath.Join(instance, "events", ev, "enable"), "0")
			}
		}
		if err := os.Remove(instance); err != nil {
			logLine(lf, "instance cleanup: %v", err)
		}
	}
	if pkg != "" {
		cmdCtx, cancelDump := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancelDump()
		res, err := exec.CommandContext(cmdCtx, "/system/bin/dumpsys", "activity", "exit-info", pkg).CombinedOutput()
		_ = os.WriteFile(filepath.Join(runDir, "activity_exit_info.txt"), res, 0644)
		if err != nil {
			logLine(lf, "dumpsys: %v", err)
		}
	}
	copyRecentTombstones(started, runDir, lf)
	logLine(lf, "stop: %s", time.Now().Format(time.RFC3339Nano))
	return nil
}

func saveJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	_ = os.WriteFile(path, append(b, '\n'), 0644)
}
func scanProcesses(ctx context.Context, pkg, dir string, lf *os.File) {
	f, err := os.OpenFile(filepath.Join(dir, "processes.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logLine(lf, "process scan unavailable: %v", err)
		return
	}
	defer f.Close()
	seen := map[string]bool{}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	scan := func() {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return
		}
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 0 {
				continue
			}
			cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if err != nil {
				continue
			}
			procName := strings.SplitN(string(cmdline), "\x00", 2)[0]
			if procName != pkg && !strings.HasPrefix(procName, pkg+":") {
				continue
			}
			pdir := fmt.Sprintf("/proc/%d", pid)
			stat, _ := os.ReadFile(filepath.Join(pdir, "stat"))
			identity := fmt.Sprintf("%d:%s", pid, strings.TrimSpace(string(stat)))
			if len(identity) > 250 {
				identity = identity[:250]
			}
			key := fmt.Sprintf("%d", pid)
			if !seen[key+identity] {
				seen[key+identity] = true
				rec := map[string]any{"timestamp": time.Now().Format(time.RFC3339Nano), "event": "process_seen", "pid": pid, "cmdline": procName}
				b, _ := json.Marshal(rec)
				fmt.Fprintln(f, string(b))
				target := filepath.Join(dir, "proc", fmt.Sprintf("%d", pid))
				_ = os.MkdirAll(target, 0755)
				for _, name := range []string{"maps", "status", "cmdline"} {
					if content, e := os.ReadFile(filepath.Join(pdir, name)); e == nil {
						_ = os.WriteFile(filepath.Join(target, name+".txt"), content, 0644)
					}
				}
			}
			tids, _ := os.ReadDir(filepath.Join(pdir, "task"))
			for _, thread := range tids {
				tid := thread.Name()
				if _, e := strconv.Atoi(tid); e != nil {
					continue
				}
				tkey := key + ":" + tid
				if seen[tkey] {
					continue
				}
				seen[tkey] = true
				comm := read(filepath.Join(pdir, "task", tid, "comm"))
				rec := map[string]any{"timestamp": time.Now().Format(time.RFC3339Nano), "event": "thread_seen", "pid": pid, "tid": tid, "comm": comm}
				b, _ := json.Marshal(rec)
				fmt.Fprintln(f, string(b))
			}
		}
	}
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}
func copyRecentTombstones(start time.Time, dir string, lf *os.File) {
	entries, err := os.ReadDir("/data/tombstones")
	if err != nil {
		logLine(lf, "tombstones unavailable: %v", err)
		return
	}
	outDir := filepath.Join(dir, "tombstones")
	copied := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "tombstone_") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.IsDir() || info.ModTime().Before(start.Add(-2*time.Second)) {
			continue
		}
		if copied >= 40 {
			break
		}
		source := filepath.Join("/data/tombstones", e.Name())
		input, err := os.Open(source)
		if err != nil {
			continue
		}
		_ = os.MkdirAll(outDir, 0755)
		output, err := os.Create(filepath.Join(outDir, e.Name()))
		if err == nil {
			_, err = io.Copy(output, input)
			_ = output.Close()
		}
		_ = input.Close()
		if err == nil {
			copied++
		}
	}
	logLine(lf, "tombstones copied=%d", copied)
}
