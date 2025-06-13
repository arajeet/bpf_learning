#!/usr/bin/python3
from bcc import BPF
import argparse
import ctypes

# ... (parser and other python code is identical) ...
parser = argparse.ArgumentParser(
    description="Trace ALL network writes (binary-safe) from a process and its children.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, required=True, help="The parent PID to trace")
args = parser.parse_args()


bpf_text = f"""
#include <linux/sched.h>

BPF_HASH(pids_to_trace, u32, u8);

struct args_t {{
    u32 fd;
    const char *buf;
}};
BPF_HASH(args_map, u64, struct args_t);

// sched_process_fork and sys_enter probes are unchanged...
TRACEPOINT_PROBE(sched, sched_process_fork) {{
    u32 parent_pid = args->parent_pid;
    u32 child_pid = args->child_pid;
    u8 *is_traced = pids_to_trace.lookup(&parent_pid);
    if (is_traced) {{
        u8 new_flag = 1;
        pids_to_trace.update(&child_pid, &new_flag);
        bpf_trace_printk("Fork detected: tracing new child PID %d", child_pid);
    }}
    return 0;
}}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *is_traced = pids_to_trace.lookup(&pid);
    if (is_traced == 0) {{ return 0; }}

    u64 syscall_id = args->id;
    if (syscall_id != 1 && syscall_id != 44) {{ return 0; }}

    u64 id = bpf_get_current_pid_tgid();
    struct args_t call_args = {{ .fd = (u32)args->args[0], .buf = (const char *)args->args[1] }};
    args_map.update(&id, &call_args);
    return 0;
}}


TRACEPOINT_PROBE(raw_syscalls, sys_exit) {{
    u64 id = bpf_get_current_pid_tgid();
    struct args_t *call_args = args_map.lookup(&id);
    if (call_args == 0) {{ return 0; }}

    long ret = args->ret;
    if (ret <= 0) {{
        args_map.delete(&id);
        return 0;
    }}

    u64 syscall_id = args->id;
    if (syscall_id != 1 && syscall_id != 44) {{
        args_map.delete(&id);
        return 0;
    }}

    char data[256];

    // *** THE FINAL FIX: Use the binary-safe read function ***
    // This reads 'ret' bytes (up to our buffer size), ignoring nulls.
    u64 size_to_read = ret;
    if (size_to_read > sizeof(data)) {{
        size_to_read = sizeof(data);
    }}
    bpf_probe_read_user(data, size_to_read, call_args->buf);

    bpf_trace_printk("PID=%d, FD=%d, SYSCALL=write/send, Bytes=%d", id >> 32, call_args->fd, ret);
    bpf_trace_printk("DATA: %s", data);

    args_map.delete(&id);
    return 0;
}}
"""

# ... (The rest of the Python code is identical) ...
b = BPF(text=bpf_text)

parent_pid = args.pid
key = ctypes.c_uint32(parent_pid)
leaf = ctypes.c_uint8(1)
b["pids_to_trace"][key] = leaf

print(f"Tracing PID {parent_pid} and its children... Press Ctrl+C to exit.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\nDetaching...")
    exit()
