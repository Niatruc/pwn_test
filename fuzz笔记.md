[https://paper.seebug.org/841/](https://paper.seebug.org/841/)

# AFL
项目地址: [https://github.com/mirrorer/afl](https://github.com/mirrorer/afl)
教程: [https://afl-1.readthedocs.io/en/latest/quick_start.html](https://afl-1.readthedocs.io/en/latest/quick_start.html)

* 快速示例
    ```sh
    # 插桩
    afl-g++ heap.cpp -o heap_afl

    mkdir input; cd input
    touch SEED.txt
    echo aaa > SEED.txt	//将SEED作为初始种子写入in文件夹中的SEED文件中

    # 以root执行以下操作(sudo -i)
    # /proc/sys/kernel/core_pattern 其中指定的文件名或管道用于在进程崩溃得到由系统捕获并传来的崩溃信息
    echo core > /proc/sys/kernel/core_pattern

    # CPU调频 https://wiki.archlinux.org/title/CPU_frequency_scaling_(简体中文)
    # performance是运行于最大频率
    cd /sys/devices/system/cpu
    echo performance | tee cpu*/cpufreq/scaling_governor

    # @@表示程序从文件中获取输入, --可能是将目标程序和前面的参数分开来
    afl-fuzz -i input -o output -- ./heap_afl @@
    # 其他参数
    # -f <file>: 表示将文件的内容作为stdin输入

    ```

* 并行模式**

    添加参数`-M <主进程输出目录>`或`-S <从进程输出目录>`. 主进程的策略是确定性检查(deterministic checks), 从进程则是进行随机调整. `-o`则指定同步输出目录.

    观察多个进程的状态: `afl-whatsup sync/`

* fuzz无源码二进制程序(qemu模式)

    安装: 运行afl项目下的`qemu_mode/build_qemu_support.sh`. 要安装`libglib2.0-dev`.

    编译出现问题:
    ```sh
    util/memfd.c:40:12: error: static declaration of ‘memfd_create’ follows non-static declaration
    static int memfd_create(const char *name, unsigned int flags)
                ^~~~~~~~~~~~
    ```
    `util/memfd.c`这个文件中定义的`memfd_create`函数和其他文件(`/usr/include/x86_64-linux-gnu/bits/mman-shared.h`)的定义冲突了. 按[https://blog.csdn.net/liyihao17/article/details/109981662](https://blog.csdn.net/liyihao17/article/details/109981662)解决问题.

    指定`AFL_PATH`: `export AFL_PATH=/home/bohan/res/afl/`. 

    添加参数`-Q`即可.

    ```sh
    ```

## 测试用例
**原则**

* 文件不要太大, 最好小于1kb
* 不要用太多测试用例, 除非这些用例相互有功能性差异.

## AFL++
项目地址: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

安装:
```sh
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

## 白皮书笔记
### 覆盖测量
afl在程序流分支节点处注入的代码用于粗略估计分支覆盖率, 代码逻辑大致如下:
```c
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++; 
prev_location = cur_location >> 1;
```
`shared_mem`是SHM共享内存中的一个64KB大小的区域, (branch_src, branch_dst) 

