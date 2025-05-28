# 内核命令行参数
* 参考: [The kernel’s command-line parameters](https://www.kernel.org/doc/html/v4.14/admin-guide/kernel-parameters.html)
* 参数项: 
    * `nokaslr`: 若编译内核时设置了`CONFIG_RANDOMIZE_BASE`, 则此项可禁止内核和模块基地址随机化. 

# 内核编译
* 参考
    * [手把手教你利用VS Code+Qemu+GDB调试Linux内核](https://zhuanlan.zhihu.com/p/105069730)
    * [编译Linux内核及最小文件系统并运行(Linux+busybox+roootfs+qemu)](https://blog.csdn.net/anqi8955/article/details/121607026)
* 步骤
    * 指定gcc: `export CC=/usr/bin/gcc-4.x`
    * 指定cpu架构: `export ARCH=x86`
    * `make x86_64_defconfig`: 根据`arch/x86`下的`defconfig`文件生成`.config`文件. 
    * `make menuconfig`: 使用图形界面添加配置项. 
        ```sh
            General setup  --->
            ----> [*] Initial RAM filesystem and RAM disk (initramfs/initrd) support
            Device Drivers  --->
            [*] Block devices  --->
                    <*>   RAM block device support
                    (65536) Default RAM disk size (kbytes)
        ```
    * `make -j8`: 编译内核(8线程). 
    * 编译成功后的内核位于: `arch/x86_64/boot/bzImage`
* 问题
    * `cc1: error: code model kernel does not support PIC mode`
        * 在Makefile中加入几行: 
            ```makefile
                # force no-pie for distro compilers that enable pie by default
                KBUILD_CFLAGS += $(call cc-option, -fno-pie)
                KBUILD_CFLAGS += $(call cc-option, -no-pie)
                KBUILD_AFLAGS += $(call cc-option, -fno-pie)
                KBUILD_AFLAGS += $(call cc-option, -no-pie)

                # optional, mute warnings on pointers signedness to speed up compilation
                KBUILD_CFLAGS += $(call cc-option, -Wno-pointer-sign)
            ```

    * `include/linux/compiler-gcc.h:121:1: fatal error: linux/compiler-gcc7.h`
        * 原因: 系统没有gcc-7编译器
        * 解决: 
            ```sh
                sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 1 # 最后一个数字是优先级

                update-alternatives --config gcc # 选择当前对话中的gcc为gcc-4.8

                gcc -v
            ```
## 交叉编译
* powerpc
    ```sh
        make ARCH=powerpc mrproper # 清除原有文件

        mkdir -p build/powerpc # 新建目录
        cp arch/powerpc/configs/mpc85xx_defconfig build/powerpc/.config # 将配置模板拷过来

        make ARCH=powerpc CROSS_COMPILE=powerpc-linux-gnu- O=./build/powerpc -j8
        # make ARCH=powerpc CROSS_COMPILE=/home/cmtest/musl/musl-cross-make-0.9.10/output/bin/powerpc-linux-musl- O=./build/powerpc -j8
    ```
# 内核开发
* 要点
    * 不能访问C库和标准C头文件
    * 必须使用GNU C
    * 内核编程缺乏像用户空间那样的内存保护机制
    * 难以进行浮点运算
        * 用户空间中做浮点运算时, 内核会捕获陷入, 并完成从整数操作到浮点数操作的模式转换. 但内核本身不能陷入. 在内核中使用浮点数时, 除了要人工保存和恢复浮点寄存器, 还有其他琐碎的事情要做. 
    * `没有内存保护机制`, `内存不分页`. 
    * 内核给每个进程只有很小一个定长堆栈. 
        * 在x86上, 在编译时设置栈大小, 可以是4K或8K. 
        * 在历史上, 内核栈大小是两页(32位是8K, 64位是16K)
    * 由于内核支持异步中断, 抢占和SMP(多处理), 因此要时刻注意同步和并发, 保证不出现竞争条件(常用到自旋锁和信号量). 
* 内核源代码
    * 内核头文件: `/usr/src/linux-headers-$(uname -r)`
    * 目录树
        * `init`: 初始化
        * `arch`: 架构
            * `<arch>/include/asm`
        * `drivers`: 驱动程序
        * `fs`: 文件系统
        * `net`: 网络
        * `mm`: 内存管理模块
        * `ipc`: 通讯
        * `kernel`: 内核运行时库(字符串操作等)
        * `include`: 内核开发需要的头文件
        * `scripts`: 
            * `extract-vmlinux`: 用来将vmlinuz等文件解析为vmlinux
* 名词
    * LKM(Loadable Kernel Module): 可加载内核模块

## 内核基础理论
* 进程
    * 写时拷贝: `fork`的时候, 只复制父进程的页表
    * 在内核中获取当前用户进程PID: 
        * `pid = current->pid;`
        * `pid = task_pid_nr(current);`

* 中断机制
    * 中断向量表(256项)
        * `异常`: 
            * 要点
                * cpu内部的中断, IF标志保持不变, 不关. 
                * 在产生时必须考虑与处理器的时钟同步. (因此异常也被称为`同步中断`)
            * 类型
                * `故障`(fault): `除零`, `缺页`, `越界`, `堆栈段错误`. 
                * `陷阱`(trap): int 3, 溢出等(有意为之). 用于系统调用. 
        * `中断`: 
            * 要点
                * cpu外的其它硬件中出现, `IF标志清零, 关中断`. `要求中断处理要快`, 不然性能低. 
                * 不用与处理器的时钟同步, 随时都可以产生. 
            * 类型
                * `非屏蔽中断`: 计算机内部硬件出错引起异常
                * `屏蔽中断`
        * 中断向量编号
            * 0-31: 异常和非屏蔽中断
            * 32-47: 由i/o设备引起的中断, 分配给屏蔽中断
            * 48-255: 软中断. 0x80为系统调用, 执行`int 0x80`后cpu切换到内核态, 执行`system_call`内核函数. 
    * 中断描述表IDT
        * 门: IDT表中的每一项(8字节)
            * 3位的门类型码
                * `中断门`: 110, DPL-0, 关中断
                * `陷阱门`: 111, DPL-0, 不关中断
                * `系统门`: 010, DPL-3 (向量号3, 4, 5, 0x80)

            <img alt="" src="./pic/linux_idt_1.jpg" width="30%" height="30%">

    * 中断上半部和下半部
        * 上半部: 快, 关中断. 硬件中断. 
        * 下半部: 开中断. 可以延后执行的任务. 可以被中断打断. 
            * `BH`(2.4之前): 对bh函数执行严格串行化. 一次只有一个cpu执行. 
            * `softirp`: 
                * 产生后不是马上可以执行, 必须等待内核的调度. 
                * 软中断不能被自己打断, 只能被硬件中断打断. 
                * 同一个软中断可运行在不同cpu. 所以软中断必须涉及为可重入的函数(允许多个cpu同时操作), 因此需要使用**自旋锁**来保护其数据结构. 
                * 软中断是静态分配的, 内核编译好后就不能改变. 添加后要重新编译内核. 
            * `tasklet`: 同一个tasklet不能运行在不同cpu, 多个不同类型的tasklet则可以并行运行在多个cpu上. 

                ```cpp
                static void tasklet_handler(unsigned long value) {
                    ......
                    // 开中断, 即可以响应其它中断
                    // 在tasklet_handler中分配内存或拿互斥体的时候, 不能睡眠
                }

                tasklet_struct my_tasklet;
                static unsigned long data = 0;
                tasklet_init(&my_tasklet, tasklet_handler, data); 
                tasklet_schedule(&my_tasklet); // 放到调度队列中等待调度

                // 处在中断上下文, 不能睡眠
                ```
            * `workqueues` 工作队列: 
                * 也在内核态运行
                * 不在中断上下文中, 因此可以睡眠
                * 能在不同进程间切换, 以完成不同工作
                * 私有工作队列: 

                    ```cpp
                    void my_func(struct work_struct *work) {
                        ......
                    }

                    struct workqueue_struct *my_queue;
                    my_queue = create_workqueue("my_queue");
                    struct work_struct my_work;
                    INIT_WORK(&my_work, my_func);
                    queue_work(my_queue, &my_work);
                    destroy_workqueue(my_queue);
                    ```

                * 共享工作队列: 

                    ```cpp
                    schedule_work(&my_work);
                    ```

        * 需要放在中断处理程序中执行的任务
            * 任务对时间非常敏感
            * 和硬件相关的任务
            * 要保证不被其它中断打断的任务

        <img alt="" src="./pic/linux_interrupt.jpg" width="30%" height="30%">
    
* 进程上下文和中断上下文
    * 上下文context: 包括寄存器变量, 进程打开的文件, 内存信息等. 
        * 用户级上下文: 正文, 数据, 用户堆栈, 共享存储区
        * 寄存器上下文: 通用寄存器, 程序寄存器, 处理器状态寄存器, 栈指针
        * 系统级上下文: 进程控制块(`task_struct`), 内存管理信息(`mm_struct, vm_area_struct, pgd, pte`), 内核栈
    * 中断上下文
        * 硬件传递过来的参数和内核需要保存的一些其它环境(主要是当前被中断的进程环境)
        * 中断上下文无关特定进程
        * 运行在中断上下文的代码不能做以下事情: 
            * 睡眠或放弃cpu. 内核在进入中断前会关闭进程调度, 一旦睡眠或放弃cpu, 系统会死机. 
            * 尝试获得信号量, 因为若没有获取信号量, 代码会睡眠, 结果同上. 
            * 执行耗时任务, 因为内核要响应大量服务和请求, 占用cpu太久会严重影响系统性能. 
            * 访问用户空间的虚拟地址. 
* 内核启动过程
    * 加电, 复位. 
    * bios启动: 上电自检, 然后对系统内的硬件设备进行检测和连接, 把测试所得数据存放到bios数据区. 从磁盘读入boot loader, 将控制权交给它. 
    * boot loader
    * os初始化
    
    <img alt="" src="./pic/linux_boot.jpg" width="30%" height="30%">

* linux文件系统
    * vfs提供一个统一接口(`file_operation`)

    <img alt="" src="./pic/linux_vfs.jpg" width="30%" height="30%">
    <br>
    <img alt="" src="./pic/linux_vfs.png" width="30%" height="30%">


* 微内核与宏内核(单一内核)
    * 微内核系统
        * windows nt, minix, mach
        * 每个模块对应一个进程, **模块之间通过消息传递机制进行通信**. 系统启动后, kernel, mm, fs系统进程在各自空间运行main函数循环等待消息. 
    * 宏内核系统
        * unix, linux
        * 内部也分模块, **模块间通信方式是一个模块调用另一个模块的导出函数**. 

## 开发
* 参考文档
    * 内核API参考文档
        * [kernelAPI](cs.bham.ac.uk/~exr/lectures/opsys/13_14/docs/kernelAPI/)
* 内联函数
    * 消除函数调用和返回带来的开销, 但会增加内存开销
    * 用于对时间要求较高的代码
    * 用`static`加`inline`限定
* linux内核嵌入式汇编
    * `__asm__ __volatile__("<asm routine>", : output : input : modify);`
    
        ```cpp
        void f(long seg) {
            long __lm;
            __asm__ __volatile__("lsll %1, %0" : "=r" (__lm) : "r" (seg));
        }

        // 对应的汇编代码如下
        // movl seg, %ebx
        // lsll %ebx, %eax
        // movl %eax, __lm
        ```
    
    * 分析汇编
        * '='表示这是输出寄存器(如果没有, 则可以在第一个冒号后面留空, 紧接第二个冒号). 
        * `output` `input` `modify`中有多个时, 可用逗号隔开. 
        * '&'表示寄存器不能重复. 
        * 寄存器`%0`, `%1`依次从`output`, `input`中用到的寄存器开始编码(如上面的代码, 则是将`__lm`变量值存到`%0`寄存器, 将`%1`寄存器的值存到`seg`变量)
        * `jne 2f`中, `2`是汇编代码段的编号(作为跳转目标), `f`表示向前(在它下面的代码), `b`表示向后(在它上面的代码). 每行汇编指令后面有`\n\t`, `\n`换行, `\t`是为了gcc把嵌入式汇编代码翻译成汇编代码时能保证换行和留有一定空格. 
        * 字母含义如下表. 

            |字母|含义|
            |-|-|
            | m, v, o | 表示内存单元 |
            | R | 表示任何通用寄存器 |
            | Q | 表示寄存器eax, ebx, ecx,edx之一 |
            | I, h | 表示直接操作数 |
            | E, F | 表示浮点数 |
            | G | 表示“任意” |
            | a, b, c, d | 表示要求使用寄存器eax/ax/al, ebx/bx/bl,  ecx/cx/cl或edx/dx/dl |
            | S, D | 表示要求使用寄存器esi或edi |

    * `asm volatile("rdtsc": "=a" (low), "=d" (high));` // 调用`rdtsc`指令, 返回64位时间戳(`tsc`寄存器), 低32位和高32位分别存于low和high变量

* hello world

    ```cpp
    /*************** hello.c ***************/
    #include <linux/init.h>
    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/moduleparam.h>
    MODULE_LICENSE("Dual BSD/GPL");
    MODULE_AUTHOR("reversefish@mallocfree.com");
    MODULE_DESCRIPTION("This is hello module");
    MODULE_ALIAS("A simple example");

    unsigned int hello_data=100;
    EXPORT_SYMBOL(hello_data);  // 导出符号. 其它地方用extern int hello_data 导入之

    static int times = 5;
    static char *who = "world";
    module_param(times, int, S_IRUSR); // 作为模块参数: insmod hello.ko times=5
    module_param(who, charp, S_IRUSR);

    static int hello_init(void)
    {
        printk(KERN_ALERT "Hello, world!\n");
        return 0;
    }

    static void hello_exit(void)
    {
        printk(KERN_ALERT "Goodbye, My Dear World!\n");
    }

    module_init(hello_init); // 注册初始化函数
    module_exit(hello_exit); // 注册退出函数

    ```
* 应用层代码

    ```cpp
    #include <stdio.h>
    #include <unistd.h>
    #include <fcntl.h>

    int main(void)
    {
        int fd, i;
        int data;
        fd = open("/dev/hello", O_RDONLY);
        if (fd < 0)
        {
            printf("open /dev/hello error\n");
            return 0;
        }
        for(i = 0; ; i++)
        {
            read(fd, &data, sizeof(data));
            printf("read /dev/hello is %d\n",data);
            sleep(1);
        }
        close(fd);
        return 0;
    }

    ```
* `Makefile`生成

    ```sh
        EXTRA_CFLAGS := -g
        obj-m = hello.o
        hello-objs := file1.o file2.o # 有多个源文件时加此行
        KVERSION = $(shell uname -r) # 内核版本号

        # 如果引用了hello2中导出的符号, 则需: 
        KBUILD_EXTRA_SYMBOLS=/mnt/hgfs/blabla/hello2/Module.symvers

        all: 
            make -C /lib/module/$(KVERSION)/build M=$(PWD) modules
        clean:
            make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
    ```

    * make以后生成`hello.ko`
    * `Kbuild`
        * make的时候, 首先读`.config`文件中的变量, 然后读`KBuild`文件. `KBuild`文件会用到`.config`文件中的变量. 
        ```sh
            # 将 <模块名>.o 编译进内核. 
            obj-y := <模块名>.o

            # Kbuild会调用`$(AR) rcSTP`所有目标文件合并到`built-in.a`文件中. 这个文件没有符号表. 
            # `built-in.a`会在后续通过`scripts/link-vmlinux.sh`链接进vmlinux中. 
            # 列表中个文件的先后顺序是重点. 允许重复文件名(成功链接的目标文件会在后面被忽略). 
            # 链接顺序也是重点. 在系统boot的时候, 它们的`module_init`/`__initcall`是按它们出现的顺序执行的. 
            obj-y += obj1.o obj2.o

            # 将 <模块名>.o 编译为模块
            obj-m := <模块名>.o

            # 编译到 lib.a 文件中
            lib-y := obj1.o obj2.o

            # 指定依赖的文件. 调用`$(CC)`生成这些目标文件, 对它们调用`$(LD) -r`, 生成 `<模块名>.o`
            <模块名>-y += obj1.o obj2.o

            # 等同于make时指定的EXTRA_CFALGS参数
            ccflags-y += -DMYVAR1=\"myvar1\"

            # 其它的还有asflags-y, ldflags-y
        ```

        * `Kbuild`的第二阶段(Stage2)会调用`modpost`程序: (引用: https://blog.csdn.net/lidan113lidan/article/details/119743237)
            * 生成`xx.mod.c`文件: 记录ko所需的其他信息. 
                ```cpp
                // *.mod.c文件都拥有相同的文件头, 生成此头文件的代码在./scripts/mod/modpost.c中
                #include <linux/build-salt.h>                                                                                                                     
                #include <linux/module.h>
                #include <linux/vermagic.h>
                #include <linux/compiler.h>
                
                BUILD_SALT;
                
                // MODULE_INFO(tag,name)宏的作用是在.modinfo段添加变量 字符串变量tag = "tag = info"
                // VERMAGIC_STRING为内核版本信息
                MODULE_INFO(vermagic, VERMAGIC_STRING);
                // KBUILD_MODNAME是cc时传入的参数, 其在Makefile.lib中定义:
                // modname_flags  = -DKBUILD_MODNAME=$(call name-fix,$(modname))
                MODULE_INFO(name, KBUILD_MODNAME);
                
                // 这个结构体记录模块信息
                __visible struct module __this_module
                __attribute__((section(".gnu.linkonce.this_module"))) = {
                    .name = KBUILD_MODNAME,
                    .init = init_module, // 模块的初始化函数
                    .arch = MODULE_ARCH_INIT,
                };
                ```
            * 生成`Module.symvers`文件: 内核和内部模块中所有`EXPORT_SYMBOL_XXX`符号信息都输出到这个文件. 这个文件的作用是在外部模块编译时告知外部模块当前内核有哪些导出符号, 以及这些导出符号的CRC值.
            * 将`xx.mod.c`编译生成`xx.mod.o`文件. 最后用`ld -r`将其与模块的`xx.o`链接, 生成可加装的模块`xx.ko`. 
    * 模块相关命令
        * `sudo insmod hello.ko`: 加载ko文件
        * `sudo rmmod hello.ko`: 卸载ko文件
        * `lsmod`: 可列出系统模块
        * `modinfo hello`
        * `dmesg | tail`: 打印最近内核输出

* ubuntu中模块自启动
    * 把模块文件放到lib目录: `/lib/modules/2.6.32.65/kernel/test/hello.ko`
    * `sudo vim /etc/modules`并添加模块名hello

* 字符设备驱动
    * `sudo insmod hello.ko`
    * `cat /proc/devices`查看安装驱动生成的设备主功能号(如251)
    * `sudo mknod /dev/hello c <主功能号> 0`创建设备节点, 这样就会在`/dev`目录下创建设备文件. 
        * `mknod [OPTION] NAME TYPE [MAJOR MINOR]`
            * `TYPE`
                * `c`: 表示字符设备
    * 编译运行客户端程序

## 头文件
* `linux/version.h`: 如要判断linux内核版本, 需要此头文件. 
    * 判断内核版本: `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`

## 常量
* `THIS_MODULE`: 定义于`include/linux/export.h`, 指向本模块(`module`结构体). 

## 常用API
* 数据传递
    * 在内核层不能直接操作用户层地址的数据, 需要拷贝. 相关API如下: 
        * `copy_from_user(to, from, len)`: 
        * `strncpy_from_user(to, from, max_len)`: 
        * `get_user(x, ptr)`: 将`ptr`指向的数据复制到`x`. 用于拷贝char或int等简单类型数据. 
    * 内核层函数对用户层变量的声明一般要加一个`__user`标识. 
    * `access_ok(addr, size)`: 判断地址是否可在内核空间中访问. 

* `kallsyms_lookup_name(const char* name)`: 根据所给符号名称, 获取符号地址. 比如传入`sys_call_table`, 可获取系统调用表的地址. 
* `call_usermodehelper`: 用于在内核层中执行用户态程序或系统命令. 

## linux内核调试
* 参考
    * [crash分析linux内核崩溃转储文件vmcore](https://blog.csdn.net/weixin_42915431/article/details/105666507)
    * [VMware上进行Linux Kernel调试](http://pwn4.fun/2017/06/24/VMware%E4%B8%8A%E8%BF%9B%E8%A1%8CLinux-Kernel%E8%B0%83%E8%AF%95/)
* `oops`
    * 两种可能: `killed`, `panic`
    * 设置`panic`
        * `etc/sysctl.conf`(改完后用`sudo sysctl -p`或`sudo echo 1 > /proc/sys/kernel/panic_on_oops`使之生效)
            * `kernel.panic_on_oops=1`
            * `kernel.panic=20`: panic error中自动重启, 等待20秒
    * oops错误码
        |-|第2位|第1位|第0位|
        |-|-|-|-|
        |0|内核|读|没有找到页|
        |1|用户模式|写|保护错误|
    * 将oops保存为文件
        * 用apt安装`kexec-tools`和`linux-crashdump`
        * 编辑`/etc/default/kexec`: `LOAD_KEXEC=true`, 重启
        * `sudo /etc/init.d/kdump start`
        * `sudo echo "c" > /peoc/sysrq-trigger`
        * `ls /var/crash/vmcore`
        * 下载和`uname -a`的版本信息匹配的内核符号: http://ddebs.ubuntu.con/pool/main/l/linux/
        * `dpkg -i linux-image-2.6.32-65-generic-dbgsym_2.6.32-65.131_amd64.ddeb` 将在`/usr/lib/debug/modules/$(uname -r)/`下生成用于调试的vmlinux
        * `sudo crash /usr/lib/debug/boot/vmlinux-2.6.32-65-generic/var/crash/vmcore`
        * 运行`bt/ps/log`查看信息
* `printk`
    * `printk(KERN_DEBUG "Here I am: %s:%i\n", __FILE__, __LINE__);`
    * 日志级别
        * `KERN_EMERG`: 紧急事件消息, 系统崩溃前提示, 表示系统不可用
        * `KERN_ALERT`: 报告消息, 表示必须立即采取措施
        * `KERN_CRIT`: 临界条件, 通常涉及严重的硬件或软件操作失败
        * `KERN_ERR`: 错误条件, 驱动程序常用之来报告硬件的错误
        * `KERN_WARNING`: 警告条件, 对可能出现问题的情况进行警告
        * `KERN_NOTICE`: 正常但又重要的条件, 用于提醒
        * `KERN_INFO`: 提示信息, 如驱动程序启动时, 打印硬件信息
        * `KERN_DEBUG`: 调试级别的信息
    * `/var/log/messages`
    * 若`klogd`没有运行, 消息不会传递到用户空间, 只能查看`/proc/kmsg`
    * `echo 8 > /proc/sys/kernel/printk`: 修改控制台的日志级别(0-8, 如果是8的话, 0-7的消息都可以显示在控制台上)
    * 实时打印`dmesg`信息: 
        * `sudo cat /proc/kmsg`
        * `tail -f /var/log/dmesg`: (在ubuntu中会说找不到这个文件)
        * `watch "dmesg | tail -20"`
    * `dump_stack`: 可以打印调用栈的信息. 
* `gdb`
    * 无法在内核中修改数据, 加断点, 单步调试, 只能查看信息
* `kdb`: 只能在2.6版旧内核使用, 需要打上补丁; 优点是不需要两台机器进行调试, 直接在本机进行操作
* `kgdb`
    * ubuntu内核已开启`KGDB`选项: `cat /boot/config-$(uname -r) | grep -i "GDB"`
    * `vmlinux`
        * Linux能够使用硬盘空间作为虚拟内存, 因此得名`vm`
        * 未压缩的内核镜像, 也是ELF文件
        * 有`.text`和`.data`
        * 没有符号表, 可以用[kdress](https://github.com/elfmaster/kdress). `kdress`会从 `System.map` 文件或者`/proc/kallsyms` 中获取符号相关的信息, 会根据这两种方式的可读性优先选取一种. 然后通过为符号表创建节头, 将获取到的符号信息重建到内核可执行文件中. 
            * `sudo ./kdress vmlinuz-$(uname -r) vmlinux /boot/System.map-$(uname -r)`
    * `vmlinuz`
        * 在`/boot/`下有. 
        * 在`vmlinux`的基础上, **经过gzip或bzip压缩而来**, **同时添加了启动和解压缩代码**(`arch/arm/boot/compressed/`下的`head.S`和`misc.c`, ). 是可以引导boot启动内核的最终镜像. 
        * 将`vmlinuz`解压为`vmlinux`: `/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux /boot/vmlinuz-$(uname -r) > vmlinux` 
    * `zImage`
        * 是`vmlinux`经过gzip压缩后的文件. 头部也有解压缩代码. 
        * 使用`LZ77`压缩算法. 
        * 适用于小内核, 比 `bzImage` 小. 
    * `bzImage`: big zImage
        * `zImage`的改进版本. 压缩率更高. 大内核一般采用这种压缩方式. 
        * 使用 gzip 实用程序将`vmlinux`文件压缩为较小的大小(通常压缩到 512KB 以下), 从而创建`bzimage`映像文件. 
    * `uImage`
        * 是`U-boot`专用的映像文件, 它是在`zImage`之前加上一个长度为`0x40`的头, 说明这个映像文件的类型, 加载位置, 生成时间, 大小等信息. 换句话说, 如果直接从`uImage`的`0x40`位置开始执行, `uImage`和`zImage`没有任何区别. 
* `strace`
* 内核配置项
    * `CONFIG_DEBUG_KERNEL`: 用于使其它调试选项可用. 
* `kprobe`
* `crash`
    * 需要文件: 
        * 下载地址: https://linuxsoft.cern.ch/centos-debuginfo/7/x86_64/
        * 找到名字类似`kernel-debug-debuginfo-2.6.32-358.el6.x86_64.rpm`和`kernel-debuginfo-common-x86_64-2.6.32-358.el6.x86_64.rpm`的包
        * `rpm -ivh`安装这两个包

## linux内核数据结构
* `file_operation`结构体: 是把系统调用和驱动程序关联起来的关键数据结构. 
* 链表
    * `<linux/list.h>`
        ```c
        struct list_head {
            struct list_head *next;
            struct list_head *prev;
        };

        // 在自定义结构体重加上list_head结构体成员
        struct myStruct {
            int i;
            struct list_head list;
        };

        // 初始化方法1
        struct myStruct s = {
            .i = 0,
            .list = LIST_HEAD_INIT(s.list)
        }
        // 初始化方法2
        INIT_LIST_HEAD(&s.list)

        // 方法3
        LIST_HEAD(my_list);

        // 遍历
        struct list_head *p;
        struct myStruct *pS;
        list_for_each(p, &s.list) {
            pS = container_of(p, struct list_head, list);
        }
        // 或者: 
        list_for_each_entry(pS, &s.list, list) {
            ... 
        }
        // list_for_each_entry_reverse, 反向遍历

        // 需要在遍历的时候删除: 
        list_for_each_entry_safe(pS, next, &s.list, list) {
            // 删除节点
        }
        ```
    * `container_of(ptr, type, member)`: 获取`ptr`指向的`type`型结构体中的`member`成员. (相当于windows内核中的`CONTAINING_RECORD`宏)
    * `list_add(struct list_head *new, struct list_head *head)`: 在head节点后插入new节点. 
    * `list_add_tail(struct list_head *new, struct list_head *head)`: 在head节点前插入new节点. 
    * `list_del(struct list_head *entry)`: 删除entry节点. 
    * `list_del_init(struct list_head *entry)`: 删除entry节点. 如果还需要继续使用entry, 则可以用这个函数将entry从链表中移除. 
    * `list_move(struct list_head *list, struct list_head *head)`: 将list节点移到head节点后面. 
    * `list_move_tail(struct list_head *list, struct list_head *head)`: 将list节点移到head节点前面. 
    * `list_empty(struct list_head *head)`: 若链表为空, 返回非零值. 
    * `list_splice(struct list_head *list, struct list_head *head)`: 将list节点指向的链表插入到head节点后面. 
    * `list_splice_init(struct list_head *list, struct list_head *head)`: 同上, 不过list指向的链表要被重新初始化. 
* 队列`kfifo`
    * 

## linux内核内存
* 分类
    * DMA-capable: 在x86, 是内存的前16M空间, 给ISA设备用. 新的PCI设备没有此限制. 
    * 普通内存
    * 高地址内存: 在内核中不能直接访问, 需要映射. 
* `void *kmalloc(size_t size, int flags); `
    * `flags`
        * `GFP_KERNEL`: 空闲内存较少时, 可能进入睡眠, 等待一个页面. 使用它来分配内存的函数必须可重入, 且不能在原子上下文(即中断上下文)中运行. 
        * `GFP_ATOMIC`: 在中断上下文或其它非进程上下文中分配内存时使用之. 
        * `GFP_USER`: 为用户空间分配内存, 可能睡眠. 
        * `GFP_HIGHUSER`: 类似`GFP_USER`, 若有高端内存, 就从高端内存分配. 
        * `__GFP_DMA`: 若指定之, 则只在DMA中分配内存. 
        * `__GFP_HIGHMEM`: 三个内存区域都用来分配内存. 

    ```cpp
    #include <linux/slab.h>
    char *ptr = (char *) kmalloc(1024, GFP_KERNEL);
    memset(pre, 0, 1024);
    kfree(ptr);
    ```

* `vmalloc`: 在虚拟空间分配. 

    ```cpp
    #include <linux/vmalloc.h>
    char *ptr = (char *) vmalloc(1024);
    if (ptr == NULL) return 0;
    memset(pre, 0, 1024);
    vfree(ptr);
    ```

* `__get_free_pages`: 分配页

    ```cpp
    // 分配2的3次方个内存页
    char *ptr = (char *) __get_free_pages(GFP_KERNEL, 3); 
    if (ptr == NULL) return 0;
    memset(pre, 0, PAGE_SIZE << 3);
    free_pages((unsigned long) ptr, 3);
    ```

* `kmem_cache_alloc`

* 区别和选择
    * `kmalloc`, `__get_free_pages`申请的虚拟内存位于物理内存映射区域(`<=896M`), 而且在物理上也是连续的, 它们与真实物理地址只有一个固定的偏移, 因此存在简单的转换关系. 
    * `kmalloc`最小32或64字节, 最大128K字节; 速度快, 但不清零; 分配太多时, 可能降低系统的响应速度(因为swap); 
    * `vmalloc`分配的一般>896M; 无法在原子上下文使用; 需要分配页表. 
    * `kmem_cache_alloc`: 用于分配大量相同大小的对象. 
    * `__get_free_pages`: 分配大块. 适用于以页为单位分配内存的情况. 

## linux内核多线程和中断处理
* `kthread_run` 和 `kthread_stop`

    ```cpp
    tatic struct task_struct * MyThread = NULL;

    static int MyPrintk(void *data)
    {
        char *mydata = kmalloc(strlen(data)+1,GFP_KERNEL);
        memset(mydata,'\0',strlen(data)+1);
        strncpy(mydata,data,strlen(data));
        while(!kthread_should_stop()) // kthread_stop后该函数返回true
        {
            SLEEP_MILLI_SEC(1000);
            printk("%s\n",mydata);
        }
        kfree(mydata);
        return 0;
    }
    static int __init init_kthread(void)
    {
        MyThread = kthread_run(MyPrintk,"hello world","mythread");
        return 0;
    }
    static void __exit exit_kthread(void)
    {
        if(MyThread)
        {
            printk("stop MyThread\n");
            kthread_stop(MyThread);
        }
    }
    module_init(init_kthread);
    module_exit(exit_kthread);
    ```

* `kernel_thread`(无法运行)
* 内核同步和互斥
    * `struct semaphore`
        * `DEFINE_SEMAPHORE(name)`
        * `sema_init(struct semaphore *sem, int val)`
        * `down(struct semaphore *sem)`: 拿不到会一直等
        * `down_interruptible(struct semaphore *sem)`: 试图拿, 拿不到时可被打断, 不再等待. 
        * `down_trylock(struct semaphore *sem)`: 试图拿, 拿不到就走了, 不会睡眠. 所以可用在中断上下文(前两个不可). 
    * `struct mutex` (2.6.16后)
        * `mutex_init(struct mutex *mutex)`
        * `DEFINE_MUTEX(mymutex)`
        * `mutex_lock(&mymutex)`: 不可唤醒
        * `mutex_unlock(&mymutex)`: 
        * `mutex_lock_interruptible(&mymutex)`: 
        * `mutex_trylock(&mymutex)`: 
    * `struct completion` (类似于`event`, 用于同步)
        * `struct completion my_completion`: 
        * `init_completion(&my_completion)`: 
        * `wait_for_completion(&my_completion)`: 
        * `complete(&my_completion)`: 唤醒一个线程
        * `complete_all(&my_completion)`: 唤醒所有线程
    * `spinlock_t`
        * `spinlock_t my_lock = SPIN_LOCK_UNLOCKED;`
        * `spin_lock_init(&my_lock)`
        * `spin_lock(&my_lock)`
        * `spin_unlock(&my_lock)`
    * `rwlock_t`
    * `atomic variables` 原子操作
        * `atomic_t v`: 
        * `atomic_t v = ATOMIC_INIT(0)`: `v = 0` 
        * `atomic_set(atomic_t *v)`: `v = i`
        * `int x = atomic_read(atomic_t *v)`: `x = v`
        * `atomic_add(i, atomic_t *v)`: `v += i`
        * `atomic_sub(i, atomic_t *v)`: `v -= i`
        * `atomic_inc(atomic_t *v)`: `v++`
        * `atomic_inc(atomic_t *v)`: `v--`
        * `set_bit(nr, void *addr)`: `*addr |= nr`
        * `clear_bit(nr, void *addr)`: `*addr &= ~(nr)`
    * `timer` 计时器
        * `timer_list s_timer`
        * `init_timer(&s_timer)`
        * `s_timer.function = &timer_handler`
        * `s_timer.expires = jiffies + HZ` `jiffies`记录着从开机到当前的时钟中断次数, `HZ`一般是一秒钟中断产生的次数, 两者相加表示一秒钟
        * `add_timer(&s_timer)`
        * `mod_timer(&s_timer, jiffies + HZ)`
        * `del_timer(&s_timer)`
    * `RCU`(Read-Copy Update)
        * 参考
            * https://blog.csdn.net/qq_35399548/article/details/122846896
        * 限制
            1. `RCU`只能保护动态分配的数据结构, 并且必须是通过指针访问该数据结构
            2. 受`RCU`保护的临界区内不能sleep
            3. 读写不对称, 对writer的性能没有特别要求, 但是reader性能要求极高. 
            4. reader端对新旧数据不敏感. 

## 网络防火墙Netfilter
* `iptables`

    <img alt="" src="./pic/linux_iptables_progress.jpg" width="70%" height="70%">

* 规则: `iptables -t filter -A INPUT -s 172.16.0.0/16 -p udp --dport 53 -j DROP`
    * `-t filter`: 表示指定filter表
        * `filter`: 
        * `nat`: 
        * `mangle`: 
    * `-A`: 追加
        * `-R`: 替换
        * `-D`: 删除
        * `-P`: 设置默认规则
        * `-F`: 清空
    * `INPUT`: 链
        * `PREROUTINE`
        * `FORWARD`
        * `POSTROUTINE`
        * `OUTPUT`
    * `-s`: 指定源地址
    * `-p`: 指定协议
    * `--dport`: 指定目的端口
    * `-j DROP`: 指定如何处理
        * `REJECT`
        * `ACCEPT`  

    <img alt="" src="./pic/linux_iptables_netfilter.jpg" width="30%" height="30%">

* `nf_hooks`
    * `struct list_head nf_hooks[NPROTO][NF_MAX_HOOKS]`: 一个全局变量, 是一个二维数组, 第一维指定协议族, 第二维指定hook类型. 
    * 注册一个netfilter hook就是在上述数组的链表中添加一个新节点. 
        ```cpp
        struct nf_hook_ops ipprint_ops = {
            .list =  {NULL,NULL},
            .hook = ipprint_func,   // 处理函数
            .pf = PF_INET, // ipv4
            //.hooknum = NF_INET_PRE_ROUTING,
            .hooknum = NF_INET_LOCAL_IN,
            .priority = NF_IP_PRI_FILTER+2 // 优先级
        };

        static int __init ipprint_init(void) {
            nf_register_hook(&ipprint_ops); // 注册钩子
            return 0;
        }


        static void __exit ipprint_exit(void) {
            nf_unregister_hook(&ipprint_ops);
        }

        ```

        * `hooknum`
            * `NF_INET_PRE_ROUTINE`: 完整性校验后, 选路确定前
            * `NF_INET_LOCAL_IN`: 选路确定后, 且数据包的目的地是本地主机
            * `NF_INET_FORWARD`: 目的地是其它主机的数据包
            * `NF_INET_LOCAL_OUT`: 来自本机进程的数据包在其离开本地主机的过程中
            * `NF_INET_POST_ROUTINE`: 在数据包离开本地主机"上线"之前. 

        <img alt="" src="./pic/linux_nf_hooks.jpg" width="30%" height="30%">

    * `sk_buff`: 
        * 头文件`include/linux/skbuff.h`
            * 其中有多个`skb_xxx`内联函数, 可用于获取以太网, xIP, TCP等协议头部偏移. 
        * 结构体成员: 
            * `head`: 缓冲区头部
            * `end`: 缓冲区尾部
            * `data`: 数据头部
            * `tail`: 数据尾部
            * `protocol`: 网络层协议. 
                * 在`uapi/linux/if_ether.h`中有一系列`ETH_P_XXX`宏, 指定了`protocol`的取值. 
        
        <img alt="" src="./pic/linux_sk_buff.jpg" width="30%" height="30%">

## Rootkit
* HOOK
    * 除非禁用寄存器 cr0 的写保护位或者修改 PTE, 否则不能够对内核的 text 段进行修改
    * `sys_call_table`
        * 获取其地址的方法: 
            * `cat /proc/kallsyms | grep sys_call_table`
            * `cat /boot/System.map-<内核版本号> | grep sys_call_table`
            * `kallsyms_lookup_name("sys_call_table")`
        * 这个表有写保护, 需要放开写保护. 
            * 改写cr0寄存器. 
                ```cpp
                    write_cr0(read_cr0() & (~0x10000));

                    // 改sys_call_table中的表项
                    
                    write_cr0(read_cr0() | 0x10000);
                ```
            * 在Ubuntu18以后版本(内核版本5.4.0-42)测试时, 发现上述代码会引发错误. 因此可用另一种方法: 
                ```cpp
                    unsigned int level;
                    pte_t* pte = lookup_address((unsigned long) sys_call_table, &level);
                    set_pte_atomic(pte, pte_mkwrite(*pte));

                    // 改sys_call_table中的表项
                    
                    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGERW));
                ```
            * gdb中查看`sys_call_table`的某一项(如, 第一项): `x/gx &sys_call_table+1`
    * 函数蹦床
        * 将原函数的前5~7个字节改成跳转指令跳到钩子. 
        * 
        ```x86asm
        push $address 
        ret
        ```

# 块I/O
* 设备类型
    
    |-|字符设备|块设备|
    |-|串口, 键盘|磁盘|
    |-|不可随机访问数据(以流的形式)|可随机访问数据|
    |-|仅需一个位置: 当前位置|需要能移动到不同位置|
    |-||内核要提供一个专门的提供服务的子系统|
    |-|-|-|
    |-|-|-|

* 扇区: 设备的最小寻址单元, 有时称为硬扇区或设备块. 
* 块: 文件系统的最小寻址单元, 有时称为文件块或IO块. 块包含一个或多个扇区. 内存中一个页包含一个或多个块. 


# netlink
* 参考
    * [一文了解linux 内核与用户空间通信之netlink使用方法](https://zhuanlan.zhihu.com/p/552291792)
* 要点
    * 基于socket
    * 用于内核空间和用户空间之间的通信
    * 异步通信机制, 消息保存在socket缓存队列(`sk_buff`)中. (**`ioctl`则是同步通信**)
    * 非可靠协议. 其尽力将数据发送到目的地, 但是可能丢包(比如OOM或有其它错误时). 若要可靠传输, 则发送者需要接收者作响应(设置`NLM_F_ACK`)
    * 支持多播. 对于每一个netlink协议类型, 可以有多达 32多播组, 每一个多播组用一个位表示. 
    * 消息
        ```cpp
        struct nlmsghdr {
            __u32 nlmsg_len; // 总长度
            __u16 nlmsg_type; // 类型(通常为0)
            __u16 nlmsg_flags; // 标识
            __u32 nlmsg_seq; // 序列号
            __u32 nlmsg_pid; // 发送者端口的id
        };
        ```

        * 消息标识
            * 常规标识
                * `NLM_F_REQUEST`: 消息是一个请求. 
                * `NLM_F_MULTI`: 消息是一个多部分消息的一部分, 后续的消息可以通过宏`NLMSG_NEXT`来获得. 结束则是`NLMSG_DONE`. 
                * `NLM_F_ACK`: 该请求需要接收者的确认. (Request for an acknowledgment on success)
                * `NLM_F_ECHO`: 消息是请求包的回传. 
            * GET请求的额外标识
                * `NLM_F_ROOT`: 返回满足条件的整个表, 而不是单个条目. 有该标志的请求通常导致响应消息设置`NLM_F_MULTI`标志. 当设置了该标志时, 请求是协议特定的, 因此, 需要在字段 `nlmsg_type` 中指定协议类型. 
                * `NLM_F_MATCH`: 返回所有满足条件(criteria)的条目. (未实现)
                * `NLM_F_ATOMIC`: 请求返回的数据应当原子地收集(GET), 预防数据在获取期间被修改. 
                    * 使用该标识的前提: 有`CAP_NET_ADMIN`功能或者uid为0. 
                * `NLM_F_DUMP`: 未实现. 
            * NEW请求的额外标识
                * `NLM_F_REPLACE`: 覆盖数据表中的条目. 
                * `NLM_F_EXCL`: 用于和 CREATE 和 APPEND 配合使用, 如果条目已经存在, 将失败. 
                * `NLM_F_CREATE`: 在表中创建一个条目(若不存在). 
                * `NLM_F_APPEND`: 表尾附加. 
* 用户层接口
    * `socket(AF_NETLINK, SOCK_RAW, <netlink_type>)`: 
        * `netlink_type`由用户指定. 用户需在`include/linux/netlink.h`定义, 如`#define NETLINK_MYSET 17`
    * `bind`
    * `sendmsg`
    * `recvmsg`
    * `close`
# syscall
* 参考: [Linux kernel system calls for all architectures](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)
# 错误记录
* 驱动编译错误记录
    * `error: ISO C90 forbids mixed declarations and code [-Werror=declaration-after-statement]`
        1. 
            ```cpp
            int a;
            void func() {
                a = 2;
                int c; // 因为在定义c之前使用了已定义变量a, 所以编译不通过
            }
            ```
        2. 在定义变量前使用了`printk`也会编译不通过. 
    * `error: too many arguments for format`
    > 检查`printk`中格式符有没有和变量一一对应. 

* 驱动异常记录
    * `error_code(0x0001) - permissions violation`
    > 在内核层直接对用户层变量调用`printk`或`str`系列函数时会有此错误. (但是`printk`打印用户层变量的**地址**(即使用`%p`)则无此问题)
    > 应该先调用`copy_from_user`等函数将用户层的数据拷到内核层, 再进行操作. 