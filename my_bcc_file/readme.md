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



### hello_fields.py

这和 hello_world.py 很接近，也是通过 `sys_clone()` 跟踪了一些新进程的创建，但是我们需要学一些新知识点：

1. `prog =` 这次我们通过变量声明了一个 C 程序源码，之后引用它。这对于需要通过命令行参数为 C 程序增加不同的指令很棒。
2. `hello()` 现在我们声明了一个 C 语言函数，而不是使用 `kprobe__` 开头的快捷方式。我们稍后调用这个函数。BPF 程序中的任何 C 函数都需要在一个探针上执行，因而我们必须将 `pt_reg* ctx` 这样的 ctx 变量放在第一个参数。如果你需要声明一些不在探针上执行的辅助函数，则需要定义成 `static inline` 以便编译器内联编译。有时候你可能需要添加 `_always_inline` 函数属性。
3. `b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")` 这里建立了一个内核探针，以便内核系统出现 clone 操作时执行 hello() 这个函数。你可以多次调用 `attch_kprobe()` ，这样就可以用你的 C 语言函数跟踪多个内核函数。
4. `b.trace_fields()` 这里从 trace_pipe 返回一个混合数据，这对于黑客测试很方便，但是实际工具开发中需要使用 `BPF_PERF_OUTPUT()` 。



### sync_timing.py

要学的知识点：

1. `bpf_ktime_get_ns()` 以纳秒为单位返回当前时间。
2. `BPF_HASH(last)` 创建一个名为 last 的 BPF hash 映射。我们使用了默认参数，所以它使用了默认的 u64 作为 key 和 value 的类型。（译者注：这里可以理解为一个储存数据用的全局变量，因为一些原因可能在 BPF 中只能使用 hash 映射这种形式作为全局变量，以便通信。）
3. `key = 0` 我们只储存一个键值对，每次存在 key 为 0 的位置即可。所以 key 固定为 0。
4. `last.lookup(&key)` 在 hash 映射中寻找一个 key 对应的 value。不存在会返回空。我们将 key 作为地址指针传入函数。
5. `last.delete(&key)` 顾名思义，移除一个键值对。至于为什么要删除，参见[这个内核 bug](https://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=a6ed3ea65d9868fdf9eff84e6fe4f666b8d14b02)。
6. `last.update(&key, &ts)` 顾名思义，传入两个参数，覆盖更新原有的键值对。`ts` 是时间戳



### sync_count.py

修改上一课的 sync_timing.py 程序，以存储所有内核中调用 `sync` 的计数（快速和慢速），并打印出来。 通过向现有的 hash 映射添加新的键值对，可以在 BPF 程序中记录此计数。



### disksnoop.py

在我的电脑上（Linux 5.4.0-149-generic），原版的disksnoop.py所输出的读写文件size大小全是0，意为着request结构体的__data_len成员为0，但这显然是不符合常理的。<br>
通过尝试发现，应该是在请求完成后，内核会将__data_len归零，而disksnoop.py中获取__data_len的方式是在请求完成后获取的，导致无法正确反映读写大小。<br>
通过修改，在发送请求时保存读写大小，从而正确输出。<br>



### hello_perf_output.py 

要学的知识点：

1. `struct data_t` 一个简单的 C 语言结构体，用于从内核态向用户态传输数据。
2. `BPF_PERF_OUTPUT(result)` 表明内核传出的数据将会打印到 “result” 这个通道内（译者注：实际上这就是 bpf 对象的一个 key，可以通过 `bpf_object["result"]` 的方式读取。）
3. `struct data_t data = {};` 创建一个空的 data_t 结构体，之后在填充。
4. `bpf_get_current_pid_tgid()` 返回以下内容：位于低 32 位的进程 ID（内核态中的 PID，用户态中实际为线程 ID），位于高 32 位的线程组 ID（用户态中实际为 PID）。我们通常将结果通过 u32 取出，直接丢弃最高的 32 位。我们优先选择了 PID（← 指内核态的）而不是 TGID（← 内核态线程组 ID），是因为多线程应用程序的 TGID 是相通的，因此需要 PID 来区分他们。通常这也是我们代码的用户所关心的。
5. `bpf_get_current_comm(&data.comm, sizeof(data.comm));` 将当前参数名填充到指定位置。
6. `reault.perf_submit()` 通过 perf 缓冲区环将结果提交到用户态。
7. `def print_event()` 定义一个函数从 `result` 流中读取 event。（译者注：这里的 cpu, data, size 是默认的传入内容，连接到流上的函数必须要有这些参数）。
8. `b["events"].event(data)` 通过 Python 从 `result` 中获取 event。
9. `b["events"].open_perf_buffer(print_event)` 将 `print_event` 函数连接在 `result` 流上、
10. `while 1: b.perf_buffer_poll()` 阻塞的循环获取结果。

这些未来的 bcc 版本中可能有所改进。 例如，Python 数据结构可以从 C 代码自动生成。



### sync_perf_output.py

使用 `BPF_PERF_OUTPUT` 重新编写 sync_timing.py。



### bitehist.py

本节课要学的知识点有：

1. `BPF_HISTOGRAM(hist)` 定义一个直方图形式的 BPF 映射（译者注：区别于之前的 hash 映射），名为 hist。
2. `dist.increment()` 第一个参数的运算结果作为直方图索引的递增量，默认为 1。自定义的递增量可以作为第二个参数提供。
3. `bpf_log2l()` 返回参数以 2 为底的对数值。 这将作为我们直方图的索引，因此我们正在构建 2 的幂直方图。
4. `b["dist"].print_log2_hist("kbytes")` 将直方图 dist 的索引打印为 2 的幂，列标题为 “kbytes”。从内核态传到用户态的唯一数据是这一系列索引项的总计数，从而提高了效率。（译者注：因为一个 2 的幂实际上对应多个索引，比如第 3 行包含了 2^2 至 2^3-1 的多个索引的计数之和。）



