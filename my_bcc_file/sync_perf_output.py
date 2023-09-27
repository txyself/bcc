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

int do_trace(struct pt_regs *ctx) {
    struct data_t data = {};

    data.ts = bpf_ktime_get_ns();

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")

# process event
start = 0
previous_time = 0
def print_event(cpu, data, size):
    global start
    global previous_time
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
            previous_time = start
    else:
        interval = event.ts - previous_time
        ts = event.ts - start
        if interval < 1000000000:
             print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, interval / 1000000))
        previous_time = event.ts

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
