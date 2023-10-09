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

