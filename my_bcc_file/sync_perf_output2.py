#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u64 ts;
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.ts = bpf_ktime_get_ns();

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="hello")

# header
# print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
previous = 0
def print_event(cpu, data, size):
    global start, previous
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    else:
        time_s = (float(event.ts - start)) / 1000000000
        interval = event.ts - previous
        if interval < 1000000000:
            printb(b"At time %.2f s: multiple syncs detected, last %d ms ago" % (time_s, interval))
    previous = event.ts
# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
