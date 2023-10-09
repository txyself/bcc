#!/usr/bin/python
#
# bitehist.py	Block I/O size histogram.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of using histograms to show a distribution.
#
# A Ctrl-C will print the gathered histogram then exit.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Aug-2015	Brendan Gregg	Created this.
# 03-Feb-2019   Xiaozhou Liu    added linear histogram.

from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct data{
    u64 ts;
	u32 len;
};

BPF_HASH(start, struct request *, struct data);

BPF_HISTOGRAM(dist);
		
int trace_start(struct pt_regs *ctx, struct request *req)
{
    struct data info = {};
    info.ts = bpf_ktime_get_ns();
    info.len = req->__data_len;
	
	start.update(&req, &info);
    return 0;
};

int trace_completion(struct pt_regs *ctx, struct request *req)
{
    struct data* info;
	info = start.lookup(&req);
	if(info != 0){
	    dist.increment(bpf_log2l(info->len / 1024));
	}
	start.delete(&req);
	return 0;
};
"""

b = BPF(text = prog)

if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
print("log2 histogram")
print("~~~~~~~~~~~~~~")
b["dist"].print_log2_hist("kbytes")
