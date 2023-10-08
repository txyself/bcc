### hello_world.py

```
from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

1. `text='...'` 这里定义了一个内联的、C 语言写的 BPF 程序。
2. `kprobe__sys_clone()` 这是一个通过内核探针（kprobe）进行内核动态跟踪的快捷方式。如果一个 C 函数名开头为 `kprobe__` ，则后面的部分实际为设备的内核函数名，这里是 `sys_clone()` 。
3. `void *ctx` 这里的 `ctx` 实际上有一些参数，不过这里我们用不到，暂时转为 `void *` 吧。
4. `bpf_trace_printk()` 这是一个简单地内核设施，用于 printf() 到 trace_pipe（译者注：可以理解为 BPF C 代码中的 `printf()`）。它一般来快速调试一些东西，不过有一些限制：最多有三个参数，一个`%s` ，并且 trace_pipe 是全局共享的，所以会导致并发程序的输出冲突，因而 `BPF_PERF_OUTPUT()` 是一个更棒的方案，我们后面会提到。
5. `return 0` 这是一个**必须的**部分（为什么必须请参见 [这个issue](https://github.com/iovisor/bcc/issues/139)）。
6. `.trace_print()` 一个 bcc 实例会通过这个读取 trace_pipe 并打印出来。

### sys_sync()

```
from bcc import BPF
BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("sys_sync() called!\\n"); return 0; }').trace_print()
```

### disksnoop.py

在我的电脑上（Linux 5.4.0-149-generic），原版的disksnoop.py所输出的读写文件size大小全是0，意为着request结构体的__data_len成员为0，但这显然是不符合常理的。<br>
通过尝试发现，应该是在请求完成后，内核会将__data_len归零，而disksnoop.py中获取__data_len的方式是在请求完成后获取的，导致无法正确反映读写大小。<br>
通过修改，在发送请求时保存读写大小，从而正确输出。<br>

