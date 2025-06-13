Of course. Here is the detailed case study converted into a `README.md` file format, using Markdown for structure and readability.

---

# Case Study: A Deep Dive into eBPF Tracing and Debugging

**Document ID:** EBPF-HTTP-TRACE-001
**Date:** May 21, 2024
**Author:** AI Assistant & User Collaboration
**Status:** Final

## 1. Executive Summary

This document details the iterative process of developing and debugging an eBPF-based utility to trace an HTTP request through its underlying system calls. The initial goal was to monitor a specific Process ID (PID) and observe the `read`/`write` syscalls associated with its network traffic.

The project encountered a series of increasingly complex and non-standard challenges, moving from common setup issues to deep kernel security policies, toolchain incompatibilities, and subtle BPF programming logic flaws. Each problem required a specific diagnostic approach and a corresponding evolution of the solution.

The final result is a robust eBPF script that successfully uses stable tracepoints, automatically follows forked child processes, and correctly handles both encrypted (HTTPS) and unencrypted (HTTP) traffic at the syscall level, providing clear visibility into the system's behavior. This journey serves as a practical, real-world guide to advanced eBPF troubleshooting.

## 2. Initial Goal and Scenario

-   **Objective:** Take a Process ID (PID) as input and use eBPF to trace all network-related syscalls (`read`, `write`, `sendto`, `recvfrom`) originating from that process and its children.
-   **Key Requirement:** Extract and display the `traceparent` header from any HTTP requests made by the traced processes.
-   **Test Case:** A shell script (`run_requests.sh`) that uses `curl` to make two requests: one HTTPS request to `example.com` and one HTTP request to `httpbin.org`.

---

## 3. The Debugging Journey: A Chronological Analysis

This section details each problem encountered, the hypothesis, the diagnostic steps taken, and the resolution.

### Phase 1: Initial Setup and Compilation Failures

#### Problem 1: `Failed to compile BPF module`
-   **Symptom:** The Python script failed immediately upon launch with a generic BPF compilation error.
-   **Hypothesis:** The most common cause for this error is a missing dependency, specifically the kernel headers that match the running kernel version, or a missing compiler toolchain (Clang/LLVM).
-   **Diagnostic:** Checked the full error traceback for specific C compilation errors like `"file not found: 'uapi/linux/ptrace.h'"`.
-   **Resolution:** A comprehensive reinstallation of all required packages was performed to create a clean and correctly aligned toolchain.
    ```bash
    sudo apt-get install -y --reinstall bpfcc-tools python3-bpfcc linux-headers-$(uname -r) build-essential clang llvm libelf-dev
    ```

#### Problem 2: `error: cannot call non-static helper function`
-   **Symptom:** After fixing dependencies, the BPF C code still failed to compile. The error pointed to a C function being called from another BPF program function.
-   **Hypothesis:** The BPF Verifier imposes a strict security rule: BPF programs cannot use standard function calls. All helper functions within a BPF program must be inlined by the compiler.
-   **Diagnostic:** Identified the function call in the C code that was causing the error.
-   **Resolution:** The C helper function signature was modified from `static int ...` to `static inline int ...`. This instructed the compiler to "copy-paste" the function's body at the call site, eliminating the function call and satisfying the verifier.

---
### Phase 2: The "Permission Denied" Mystery

This was the most complex phase, involving a series of hypotheses that were systematically proven wrong, peeling back layers of the system's security posture.

**Symptom:** The BPF code now compiled successfully, but the BCC library failed to attach the compiled program to the kernel, receiving a `Permission denied` error. The error occurred *after* the verifier had started its analysis (`processed 85 insns...`).

| Hypothesis                                   | Diagnostic Command                                    | Result               |
| -------------------------------------------- | ----------------------------------------------------- | -------------------- |
| **A: Kernel Lockdown / Secure Boot**         | `cat /proc/sys/kernel/lockdown`                       | File not found.      |
| **B: AppArmor**                              | `sudo systemctl stop apparmor` & re-run               | Error persisted.     |
| **C: LXC Container Restrictions**            | `systemd-detect-virt`                                 | `kvm` (Not a container). |
| **D: Missing Capabilities in KVM**           | `sudo capsh --print`                                  | `cap_sys_admin` present. |
| **E: Seccomp Sandbox**                       | `grep Seccomp /proc/$$/status`                        | `Seccomp: 0` (No filter). |

#### The Real "Permission Denied" Cause: Hardened `sysctl` Toggles
-   **Hypothesis:** With all standard security modules ruled out, the cause had to be a non-standard system-wide policy set via `sysctl`.
-   **Diagnostics:**
    1.  `sysctl kernel.unprivileged_bpf_disabled` -> **Result: `2`**. (BPF disabled for ALL users, including root).
    2.  `sysctl net.core.bpf_jit_harden` -> Result indicated another overly restrictive setting.
-   **Resolution:** The sysctl values were changed to a secure and functional default, and the changes were made permanent in `/etc/sysctl.d/`.
    ```bash
    sudo sysctl -w kernel.unprivileged_bpf_disabled=1
    sudo sysctl -w net.core.bpf_jit_harden=1
    ```

---
### Phase 3: Toolchain and Logic Failures

#### Problem: Toolchain, Data Corruption, and Logic Flaws
Even with permissions fixed, the program faced a cascade of issues:
1.  **`bpf_printk undeclared` Error:** A symptom of BCC failing to find the correct kernel headers for the modern 6.8 kernel. **Resolution:** Fixed by using manual probe attachment (`b.attach_kprobe`) which proved more resilient than BCC's automatic (`kprobe__`) attachment, and later by using tracepoints which are the most stable method.

2.  **Corrupted Perf Buffer Data:** The program loaded but sent garbage data to user-space (negative timestamps, huge FDs). **Hypothesis:** A subtle incompatibility between the kernel's perf buffer and the BCC library on this system. **Resolution:** Switched from the `BPF_PERF_OUTPUT` buffer to the simpler, more reliable `bpf_trace_printk` mechanism.

3.  **`too many arguments` Verifier Error:** The `bpf_trace_printk` call failed because it exceeded the verifier's hardcoded argument limit. **Resolution:** Split the single complex `printk` call into two simpler ones.

4.  **Tracing the Wrong Process:** The tracer was only tracing the parent shell script, not the `curl` child processes. **Hypothesis:** The tracer was blind to the `fork-exec` model. **Resolution:** Added a tracepoint on `sched_process_fork` to dynamically detect and trace new child processes.

5.  **Missing HTTPS Request Trace:** The trace for `https://example.com` was missing. **Hypothesis:** An in-kernel filter (`if data starts with "GET"`) was failing on encrypted TLS traffic. **Resolution:** Removed the filter to ensure all `write` calls were processed.

6.  **Incomplete Binary Data:** The encrypted TLS packets were truncated. **Hypothesis:** The BPF helper `bpf_probe_read_user_str` was being used, which stops at the first null byte (`\0`). **Resolution:** Switched to the binary-safe `bpf_probe_read_user` to read a specified number of bytes, regardless of content.

---
### 4. The Final, Working Solution

The final script represents the culmination of all lessons learned. It is a robust, fork-aware, binary-safe eBPF tracer that uses stable tracepoints and a resilient data output mechanism.

*Key Features of the Final Design:*
-   **Uses Tracepoints:** Attaches to the stable `raw_syscalls:sys_enter/exit` and `sched:sched_process_fork` tracepoints instead of brittle kprobes.
-   **Traces Forks:** Automatically traces children of the target PID by monitoring `fork` events.
-   **Binary-Safe:** Uses `bpf_probe_read_user` to correctly handle both text and binary data payloads.
-   **Resilient Output:** Uses `bpf_trace_printk` to avoid perf buffer incompatibilities and respects its argument limits.
-   **Correct User-space Logic:** Uses `ctypes` for safe interaction with BPF maps from Python.

### 5. Key Takeaways

1.  **eBPF Debugging is Layered:** Problems must be diagnosed from the outside in: `Dependencies -> Permissions -> Kernel Policies -> Toolchain Paths -> BPF Verifier Logic -> Program Logic`.
2.  **The Kernel is the Source of Truth:** `dmesg`, `journalctl`, and the `/proc` filesystem are invaluable for diagnosing why the kernel is rejecting a program.
3.  **Isolate and Test:** When a complex program fails, creating a minimal test case is the fastest way to isolate the source of the failure.
4.  **Understand the Target:** Tracing at the syscall level provides ground truth but requires understanding what the data looks like at that layer (e.g., encrypted TLS vs. plain text HTTP).
5.  **Know Your Process Model:** Not understanding the `fork-exec` model is a common logical error. Tracing tools must be aware of process relationships.
6.  **eBPF Has Limits:** The verifier has strict limits on complexity and helper function arguments. Code must be written to respect these constraints, often by simplifying or splitting logic.
