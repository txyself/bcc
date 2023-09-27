from bcc import BPF

prog = """
int hello(void *ctx){
    bpf_trace_printk("Hello, sync!\\n");
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(b.get_syscall_fnname("sync"), fn_name="hello")

print("%-18s %-16s %-6s %s" % ("Time(s)", "COMM", "PID", "MESSAGE"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
