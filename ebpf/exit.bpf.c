// Exit Tracer V2: generic read-only signal / process-exit telemetry
// Tracepoint layout is checked against device tracefs format at deployment.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EVENT_EXIT 1
#define EVENT_SIGNAL_GENERATE 2
#define EVENT_SIGNAL_DELIVER 3
#define EVENT_SYSCALL_ENTER 4
#define STACK_DEPTH 32

struct event {
    __u64 timestamp_ns;
    __u32 actor_tgid;
    __u32 actor_tid;
    __u32 target_tid;
    __u32 kind;
    __u32 sig;
    __s32 code;
    __s32 stack_id;
    char comm[16];
    __u32 syscall_nr;
    __u64 arg0;
    __u64 arg1;
    __u64 arg2;
};

struct trace_exit {
    __u64 common;
    char comm[16];
    __s32 pid;
    __s32 prio;
};
struct trace_sig_generate {
    __u64 common;
    __s32 sig;
    __s32 err;
    __s32 code;
    char comm[16];
    __s32 pid;
    __s32 group;
    __s32 result;
};
struct trace_sig_deliver {
    __u64 common;
    __s32 sig;
    __s32 err;
    __s32 code;
    __u32 pad;
    __u64 handler;
    __u64 flags;
};
struct trace_raw_sys_enter {
    __u64 common;
    __s64 id;
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

// Optional target thread set, updated by the userspace daemon.
// No target set (mode=0): capture all relevant signals and exits.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u32);
} target_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

static __always_inline int selected(__u32 tgid, __u32 tid, __u32 target) {
    __u32 zero=0;
    __u32 *mode=bpf_map_lookup_elem(&config,&zero);
    if (!mode || *mode == 0) return 1;
    __u32 *matched=bpf_map_lookup_elem(&target_tids,&tid);
    if (matched && *matched == tgid) return 1;
    if (target) {
        matched=bpf_map_lookup_elem(&target_tids,&target);
        if (matched) return 1;
    }
    return 0;
}
static __always_inline int keep_sig(int sig) {
    return sig==4 || sig==5 || sig==6 || sig==7 || sig==8 || sig==9 || sig==11 || sig==15;
}
static __always_inline int emit(void *ctx, __u32 kind, __u32 sig, __s32 code, __u32 target) {
    __u64 id=bpf_get_current_pid_tgid();
    __u32 tgid=id>>32;
    __u32 tid=(__u32)id;
    if (!selected(tgid,tid,target)) return 0;
    struct event e={};
    e.timestamp_ns=bpf_ktime_get_ns();
    e.actor_tgid=tgid;
    e.actor_tid=tid;
    e.target_tid=target;
    e.kind=kind;
    e.sig=sig;
    e.code=code;
    e.stack_id=bpf_get_stackid(ctx,&stacks,BPF_F_USER_STACK);
    bpf_get_current_comm(&e.comm,sizeof(e.comm));
    bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&e,sizeof(e));
    return 0;
}
SEC("tracepoint/sched/sched_process_exit")
int on_exit(struct trace_exit *ctx) {
    return emit(ctx,EVENT_EXIT,0,0,ctx->pid);
}
SEC("tracepoint/signal/signal_generate")
int on_signal_generate(struct trace_sig_generate *ctx) {
    if (!keep_sig(ctx->sig)) return 0;
    return emit(ctx,EVENT_SIGNAL_GENERATE,ctx->sig,ctx->code,ctx->pid);
}
SEC("tracepoint/signal/signal_deliver")
int on_signal_deliver(struct trace_sig_deliver *ctx) {
    if (!keep_sig(ctx->sig)) return 0;
    return emit(ctx,EVENT_SIGNAL_DELIVER,ctx->sig,ctx->code,0);
}
SEC("tracepoint/raw_syscalls/sys_enter")
int on_raw_sys_enter(struct trace_raw_sys_enter *ctx) {
    // AArch64 Linux syscall numbers (asm-generic/unistd.h).
    // exit=93, exit_group=94, kill=129, tkill=130, tgkill=131.
    __s64 nr=ctx->id;
    if (nr!=93 && nr!=94 && nr!=129 && nr!=130 && nr!=131) return 0;
    __u32 target=0;
    if (nr==129 || nr==130) target=(__u32)ctx->args[0];
    if (nr==131) target=(__u32)ctx->args[1];

    __u64 pidtid=bpf_get_current_pid_tgid();
    __u32 tgid=pidtid>>32;
    __u32 tid=(__u32)pidtid;
    if (!selected(tgid,tid,target)) return 0;

    struct event e={};
    e.timestamp_ns=bpf_ktime_get_ns();
    e.actor_tgid=tgid;
    e.actor_tid=tid;
    e.target_tid=target;
    e.kind=EVENT_SYSCALL_ENTER;
    e.syscall_nr=(__u32)nr;
    e.arg0=ctx->args[0];
    e.arg1=ctx->args[1];
    e.arg2=ctx->args[2];
    if(nr==93 || nr==94) e.code=(__s32)e.arg0;
    if(nr==129 || nr==130) e.sig=(__u32)e.arg1;
    if(nr==131) e.sig=(__u32)e.arg2;
    e.stack_id=bpf_get_stackid(ctx,&stacks,BPF_F_USER_STACK);
    bpf_get_current_comm(&e.comm,sizeof(e.comm));
    bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&e,sizeof(e));
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
