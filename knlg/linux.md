# 文件
* `proc`: 其下每个目录对应一个进程; 各个进程目录下有如下文件: 
    * `map`: 文件保存了一个进程镜像的布局(可执行文件, 共享库, 栈, 堆和 VDSO 等)
    * `kcore`: Linux 内核的动态核心文件. 
    * `kallsyms`: 内核符号. 如果在 `CONFIG_KALLSYMS_ALL` 内核配置中指明, 则可以包含内核中全部的符号. 
* `boot`:
    * `System.map`: 内核符号. 
# 开发
* code blocks
    1. `sudo apt install codeblocks`: 
    2. `sudo apt install build-essential`: 
    3. `sudo apt install valgrind`: 用于探测内存泄露的调试组件
    3. `sudo apt install codeblocks-contrib`: 安装codeblocks常用插件
* gcc
    * `-static`: 静态编译
    * `-I <头文件目录>`
    * `-Wl,`: 其后紧接的参数是传给链接器ld的. 
        * `-Map=<map文件路径>`: 生成map文件
        * `-Bstatic -l<库名>`: 指定静态链接库
        * `-Bdynamic -l<库名>`: 指定动态链接库
        * `--as-needed`: 可忽略不被依赖的库, 进而加快程序的启动. 
    * `-xc xxx`: 以编译C语言代码的方式编译xxx文件
* make
    * 指定`make install`的安装位置: 先执行`./configure --prefix=<目标路径>`
    * `-C $(DIR) M=$(PWD)`: 跳转到源码目录`$(DIR)`下, 读其中的Makefile. 然后返回到`$(PWD)`目录. 

# 调试
## GDB
* 启动参数: 
    * `-tui`: 同时打开源程序
    * 设置程序运行参数
        * `gdb --args <程序路径> <程序参数>`
        * 在进入gdb后, 可以`run <程序参数>`
        * 在进入gdb后, 可以`set args <程序参数>`
* coredump: 
    * 设置coredump文件限制大小为无限大: `ulimit -c unlimited`
    * 设置coredump文件生成路径(以root身份): `echo "/my_dir/core-%e-%t-%s-%p" > /proc/sys/kernel/core_pattern`, 其中: 
        * `%e`: 进程名
        * `%t`: 时间戳
        * `%s`: 引起coredump的signal号
        * `%p`: 进程id
    * `gdb <可执行文件> <coredump文件>`
* 基本命令
    * `attach <pid>`: 附加进程
    * `start`: 运行程序, 停在第一行
    * `r`: 运行. 
    * `c`: 继续运行. 
    * `n`: 单步跳过
    * `s`: 步入
        * `si`: 执行单条指令
    * `finish`: 跳出函数
    * `bt`: 调用栈
    * `l`: 查看源代码
        * `<行号>`: 列出第`<行号>`行代码
        * `<函数名>`: 
    * 打印数值
        * `display a`: 显示变量a的值
        * `x/<FMT> <addr>`
            * 例: `x/10xw &a`: 以16进制的格式, 打印变量a的地址开始后的10个四字节数据. 
            * 格式可选: o(8进制), x(16进制), d(十进制), u(无符号十进制), t(二进制), f, a(地址), i(指令), c(字符), s(字符串), z(左侧零填充的16进制)
            * 大小可选: b(1字节), h(2), w(4), g(8)
        * `i`: 
            * `breakpoints`: 显示所有断点
            * `locals`: 显示所有局部变量
            * `registers`: 显示所有寄存器
    * 断点
        * `b <filename>:<function name>`
        * `delete n`: 删除第n个断点
    * `layout`: 界面
        * `src`: 源程序
        * `asm`: 汇编
        * `split`: 源程序和汇编各一个窗口
    * `tui enable`: 源程序界面. 可以用`ctrl+x, a`切换. 
    * 设置
        * `set follow-fork-mode child`: 设置gdb在fork之后跟踪子进程. 
        * `set var a = 1`: 设置变量a的值为1

# 字符串
* api
    * `char *strtok(char s[], const char *delim);` 当发现`delim`中包含的分隔符时, 会将该字符改为`\0`. 首次调用时, 参数`s`是目标字符串, 后面调用时直接设为NULL. 直到`strtok`返回NULL, 则说明分割结束了. 
    * `bzero(buf, len)`: 将缓冲区`buf`的`len`个字节清零. 

# 进程
* api
    * `FILE * popen(const char *command , const char *type );`
        * 创建一个管道, 调用`fork`产生一个子进程, 执行`command`命令. 管道须由`pclose`关闭. 
        * `type`: 'r'则返回进程的标准输出流, 'w'则为标准输入流. 
    * `getpid`: 获取本进程id
    * `getppid`: 获取父进程id
    * `fork`: 创建子进程, 其从调用`fork`之后的地方开始执行.     
        * 返回值
            * 负值: 创建子进程失败. 
            * 零: 返回到新创建的子进程. (即若返回值为0, 表面此时在子进程中)
            * 正值: 返回父进程. 该值包含新创建的子进程的进程ID. (即若返回值大于0, 表面此时在父进程中)
    * `int kill(pid_t pid, int sig);` 向`pid`进程发送`sig`信号. 
    * `signal(int sig, void (*func)(int))`: 设置`func`函数, 来等待`sig`信号. 
        * 头文件: `<signal.h>`
        * 一些常用信号
            |信号常量|信号含义|
            |-|-|
            |SIGABRT|	(Signal Abort) 程序异常终止. |
            |SIGFPE|	(Signal Floating-Point Exception) 算术运算出错, 如除数为 0 或溢出（不一定是浮点运算）. |
            |SIGILL|	(Signal Illegal Instruction) 非法函数映象, 如非法指令, 通常是由于代码中的某个变体或者尝试执行数据导致的. |
            |SIGINT|	(Signal Interrupt) 中断信号, 如 ctrl-C, 通常由用户生成. |
            |SIGSEGV|	(Signal Segmentation Violation) 非法访问存储器, 如访问不存在的内存单元. |
            |SIGTERM|	(Signal Terminate) 发送给本程序的终止请求信号. |
            |SIGPIPE|	网络异常时, 使用socket相关函数如`send`等会触发此信号(提示`Broken Pipe`). |
    * `int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);`
        * 参数
            * `signum`: 不可以是`SIGKILL`或`SIGSTOP`. 
            * `act`: 
                ```cpp
                // #include <signal.h>
                struct sigaction {
                    union {
                        void (*sa_handler)(int); 
                        void (*sa_sigaction)(int, siginfo_t *, void *); // 若设置了SIGINFO_T, 则用这个函数
                    } __sigaction_handler; // 新的信号处理函数

                    // 在处理信号时会暂时将 sa_mask 指定的信号集搁置
                    sigset_t sa_mask;

                    // 用来设置信号处理的其他相关操作
                    // A_NOCLDSTOP: 如果参数signum为SIGCHLD, 则当子进程暂停时并不会通知父进程
                    // SA_ONESHOT/SA_RESETHAND: 当调用新的信号处理函数前, 将此信号处理方式改为系统预设的方式
                    // SA_RESTART: 被信号中断的系统调用会自行重启
                    // SA_NODEFER : 一般情况下,  当信号处理函数运行时, 内核将阻塞该给定信号. 但是如果设置了 SA_NODEFER标记,  那么在该信号处理函数运行时, 内核将不会阻塞该信号
                    int sa_flags;

                    void (*sa_restorer)(void);
                }
                ```
            * `oldact`: 用于保存原来对信号的处理. 
        * 返回: 0成功, -1失败. 
    * `int sigqueue(pid_t pid, int sig, const union sigval value);` 类似`kill`, 主要针对**带参的信号**. `value`为传递的参数. 
        * 例: 
            ```cpp
            pid_t pid = atoi(argv[1]);
            union sigval v;
            v.sival_int = 100;
            sigqueue(pid, SIGINT, v);

            void my_handler(int sig, siginfo_t *info, void *ctx) {

            }
            ```
    * `pid_t waitpid(pid_t pid,int * status,int options)`: 暂停进程, 等待信号到来或pid子进程结束. 
    * `exec`系列: 将执行从原进程转到新进程. 若成功则原进程不再执行. (成功则不返回, 失败则返回-1)
        * `int execvp(const char *file ,char * const argv [])`: 执行可执行文件. 
    * `system`: 执行bash命令. 如果不是运行为后台进程, 则要等进程结束该函数才返回. 返回退出码(错误返回-1)

# 文件
* api
    * `int fd = open(const char *pathname,int flags,mode_t mode);` 
        * `flags`
            * 主类: 
                * `O_RDONLY`: 只读   
                * `O_WRONLY`: 只写   
                * `O_RDWR`: 读写
            * 副类: 
                * `O_CREAT`: 文件不存在则创建文件
                * `O_EXCL`: 用了`O_CREAT`但文件存在, 则返回错误消息
                * `O_NOCTTY`: 若文件为终端设备, 则不会将该终端机当成进程控制终端机
                * `O_TRUNC`: 若文件已存在, 删除文件中原有数据
                * `O_APPEND`: 以追加的方式打开    
    * `ssize_t write(int fd,const void * buf,size_t count);` 
        * `buf`: 存放要写入的内容
        * `count`: 要写入的字节数
        * 返回值: 
    * `int fileno(FILE *stream)`: 获得文件流所使用的文件描述符. 
    * `int isatty(int desc)`: 判断文件描述符指向的文件是否是终端. 
    * `perror(char *s)`: 将上一个函数发生错误的原因输出到stderr. `s`所指向的字符串会先被打印. 
    * `termios.h`
        * `int tcgetattr(int fd, struct termios *termios_p);` 获取终端参数, 保存于`termios`结构体. 
    * `fd_set`: 这个结构体的变量用于存放文件描述符. 
        * `FD_ZERO(fd_set*)`: 清空一个fd_set. 
        * `FD_SET(int, fd_set*)`: 将一个fd加入到一个fd_set中. 
        * `FD_CLR(int, fd_set*)`: 将一个fd从一个fd_set移除. 
        * `FD_ISSET(int, fd_set*)`: 检测一个fd是否在一个fd_set中, 是则返回true. 
        * `int select(int maxfdp, fd_set* readfds, fd_set* writefds, fd_set* errorfds, struct timeval* timeout)`
            * 用于监视文件描述符的变化情况(读写或异常). 比如检查套接字是否有数据可读了. 这个函数会将未准备好的描述符位清零. 
            * 参数: 
                * `maxfdp`: 最大fd值加一
                * `readfds`: 用于检查可读性
                * `writefds`: 用于检查可写性
                * `errorfds`: 用于检查异常
                * `timeout`: 用于决定select等待I/O的最长时间, 在此期间select函数会阻塞. 为NULL则无限等待. 
                    * `timeout->tv_sec`或`timeout->tv_usec`不为0时, 等待指定的时间. (前者为秒, 后者为微秒)
            * 返回值
                * 满足要求的描述符的个数
                * -1: 出错
                * 0: 超时
        
        * 示例: 读一个socket
            ```cpp
            while(1) {     
                FD_ZERO(&set); // 将set清空 
                FD_SET(s, &set); // 将套接字s加入set
                select(0, &set, NULL, NULL, NULL); //检查set集合中的套接字是否可读
                if(FD_ISSET(s, &set) { // 检查s是否在set中
                    recv(s, buf, len, 0); // 四参是flags, 一般设为0
                } 
                //do   something   here 
            }
            ```


# 网络
* api
    * `int socket(int domain, int type, int protocol);`
        * 头文件: `<sys/socket.h>`
        * 参数
            * `domain`: 协议族, 有`AF_INET`(Address Family, 也可写成`PF_INET`)和`AF_INET6`. 
            * `type`: 传输方式, 字节流`SOCK_STREAM`, 数据报`SOCK_DGRAM`, 原始套接字`SOCK_RAW`
            * `protocol`: 使用的协议, 通常有`IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_IP`
        * 返回值: 返回一个文件描述符, 如果失败, 则返回-1
        * 注: 
            * 使用小于1024的端口需要root权限
            * 普通用户使用`原始套接字`时会权限不允许的问题. 
    * `int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);`
        * 设置套接字选项. `recv`函数默认为阻塞模式, 没有数据来就会一直阻塞. 这时就可以用`setsockopt`设置超时. 
        * 参数
            * `optname`
                * `SO_RCVTIMEO`: 设置接收超时时间. 
                * `SO_SNDTIMEO`: 设置发送超时时间. 
                * `SO_RCVBUF`: 为接收确定缓冲区大小. 
                * `SO_SNDBUF`: 指定发送缓冲区大小. 
            * `optval`: 可设为一个`struct timeval*`值, 以指定超时时间. 
                * `setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out))`
    * `int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);` 将网络地址和端口与套接字绑定. 
    * `int listen(int sockfd, int backlog);` 监听向套接字`sockfd`发来的连接. 
        * 参数
            * `backlog`: 队列长度, 超过这个长度后, 后续的连接请求都被取消. (`cat /proc/sys/net/ipv4/tcp_max_syn_backlog`, `vim /etc/sysctl.conf`)
    * `int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);` 
        * 阻塞, 等待新连接. 
        * 参数
            * `addr`: 用于接收新连接的对端IP和端口等信息. 
            * `addrlen`: 传入`sizeof(sockaddr)`; 返回时得到真正接收到地址结构体的大小. 
        * 返回值
            * 成功: 返回一个新的套接字, 用于和客户端通信. 这个socket在此次通信结束后就关闭, 而监听的socket还一直处于开启中. 
            * 失败: 返回-1, 设置errno
    * `ssize_t send(int sockfd, const void *buf, size_t len, int flags);`
        * 用于TCP协议发送数据
        * 参数
            * `sockfd`: 套接字
            * `buf`: 要发送的数据
            * `len`: 数据长度
            * `flags`: 一般设为0(发送不成功则会阻塞)
                `MSG_DONTROUTE`: 不要使用网关来发送封包, 只发送到直接联网的主机. 这个标志主要用于诊断或者路由程序. 
                `MSG_DONTWAIT`: 操作不会被阻塞. 
                `MSG_EOR`: 终止一个记录. 
                `MSG_MORE`: 调用者有更多的数据需要发送. 
                `MSG_NOSIGNAL`: 当另一端终止连接时, 请求在基于流的错误套接字上不要发送SIGPIPE信号. 
                `MSG_OOB`: 发送out-of-band数据(需要优先处理的数据), 同时现行协议必须支持此种操作. 

    * `int sendto ( int s , const void * msg, int len, unsigned int flags, const struct sockaddr * to , int tolen ) ;`

    * 例子: 
        ```cpp
        #include <sys/types.h> 
        #include <sys/socket.h>


        ```

# ELF文件
* 工具
    * [XELFViewer](https://github.com/csky6688/xelfviewer)
* `DT_DEBUG`
    * https://blog.csdn.net/weixin_30416493/article/details/116879798 
    * 通过got表第一项`_DYNAMIC`指向的地方的`DT_DEBUG`的值指向的结构体(其中的第二项`r_map`指向的结构体的第一项的值是ELF文件载入内存的偏移值), 在linux下获取模块基址. 实验发现, 开启了RELRO时got表的第一项是无效的, 该方法也没用了.
* 显式链接和隐式链接
    * 指定加载动态库的方式. 
    * 隐式: 
        * 编译后, ELF文件中只保存链接库名字, 不带路径. 
        * 库的搜索顺序: `/lib` -> `ld.so.conf` -> `LD_LIBRARY_PATH`
    * 显式: 
        * `gcc`编译时指定: 
            * `-Wl,--dynamic-link=<ld库路径>`: 会将elf文件的`Sections`中`.interp`节的`Interpreter`值改成`<ld库路径>`
            * `-Wl,--rpath=<glibc目录路径>`: 指定优先搜索路径. 
        * 例: 
            * `gcc -Wl,--dynamlic-link=./my_lib/ld-2.31.so -Wl,--rpath=./my_lib/`
            * 注意`./my_lib/`必须是目标运行环境中的合法路径. 所以这里需把程序依赖的libc库拷到目标机, 和目标可执行文件放到同一目录下, 并命名为`mylib`. 
            

* 问题
    * 运行elf文件时提示"无此文件"
        * 运行`readelf -a <文件>` 查看文件头, 发现如下信息, 提示缺少musl库(一个轻量级标准C库, 类似于glibc, 多见于嵌入式系统). 执行`sudo apt-get install musl`.

            <img alt="require_musl" src="./pic/require_musl.png" width="50%" height="50%">



# bash

* 常量
    * `BASH_SOURCE`: 当前文件路径
        * `dirname BASH_SOURCE[0]`: 可获得当前文件所在目录的路径
    * `$@`: 表示目标文件
    * `$^`: 表示所有依赖文件
    * `$<`: 表示第一个依赖文件
    * `$?`: 表示比目标还新的依赖文件列表

## 系统指令, 工具
* 权限
    * `chmod`: 修改文件的rwx权限. 
        * `u+s`: 赋予(可执行)文件s权限, 文件在执行时具有文件所有者的权限(免了sudo). 
    * `setcap`
        * 
    * 修改登录口令策略
        1. 安装`libpam-cracklib`
        2. 打开`/etc/pam.d/common-password`
        3. 把有`pam_cracklib.so`那一行注释掉
        4. 把有`pam_unix.so`那一行改成: `password [success=1 default=ignore] pam_unix.so minlen=1 sha512`, 表示最短口令长度为1
* 进程
    * `fuser`: 找出正在使用某个文件或目录的进程. 
        * `fuser -v <文件名>`
    * `pkexec --user <用户名> <可执行文件>`: 允许以其他用户身份执行程序. 未指定用户, 则以root运行. 
    * `strace`: 跟踪进程的调用和信号. 
        * `-f -p <pid> -o <输出文件>`
        * `-s <长度>`: 对于字符串参数, 最大打印长度. 默认为32. 
        * `-e trace=<调用类型>`: 跟踪特定类型的接口, 这些类型有: 
            * `%file`: 文件相关调用
            * `%process`: 进程管理相关调用, 如`fork`, `exec`, `exit_group`
            * `%network`: 网络通信相关调用, 如`socket`, `sendto`, `connect`
            * `%signal`: 信号相关调用, 如`kill`, `sigaction`
            * `%desc`: 文件描述符相关调用, 如`write`, `read`, `select`, `epoll`
            * `%ipc`: 进程通信相关调用, 如`shmget`等. 
        * `-e read=3`: 查看读入到文件描述符3中的所有数据. 
    
* 文件和目录
    * `ls`
        * `-F`: 后缀表示文件类型
            * `/`: 目录
            * `*`: 可执行文件
            * `@`: 符号链接
            * `=>`: 目录
            * `|`: 目录
    * `find <目录>`: 在目录下寻找符合条件的文件
        * `-name <通配符表达式>`: 查找符合名称的文件
        * `-type l`: 列出所有符号链接
        * `-xtype l`: 列出指向不存在的文件的符号链接
* 网络 
    * `ss`: 类似`netstat`
        * `-t`: 打印TCP连接
        * `-u`: 打印UDP连接
* 系统信息
    * `uname`
        * `-r`: 查看内核版本. 
* 文本
    * `grep`
        * `-v <字符串>`: 反向查找, 即查找不包含`<字符串>`的行. 
    * `watch`
        * `watch -n 1 <命令>`: 每隔1秒执行一次`命令`, 并回显
    * `tail <文件>`: 默认显示文件后10行. 
        * `<> | tail -20`
* ELF工具
    * `strip <可执行文件>`: 将可执行文件中的调试信息去除. 
    * `dress`
    * `readelf`: 显示elf文件的信息
        * `-s`: 列出符号表
    * `ldd`
        * `--version`: 可得到glibc版本
        * `<可执行程序>`: 看目标程序依赖的库的名称及路径. 
    * `xdd`
        * 查看16进制
    * `objdump <elf文件>`: 反编译ELF文件, 其依赖ELF头. 
        * `-D`: 反汇编
        * `-d`: 只反汇编代码部分
        * `-tT`: 打印所有符号
    * `objcopy`: 
        * `–only-section=.data <infile> <outfile>`: 将`.data`节从一个ELF文件复制到另一个文件中. 
    * `ltrace`: 会解析共享库, 即一个程序的链接信息, 并打印出用到的库函数. 
        * `<elf文件> -o <输出文件>`
    * `ftrace`: https://github.com/elfmaster/ftrace
    * `nm xx.so`: 列出object文件的符号
        * `-c`: 查看导出函数表
* 编译工具
    * `make`
        * Makefile
            ```sh
            all: haha.text target1

            target1: $(MAKE) -C /lib/modules/5.4.0-42-generic/build M=/home/u1/output src=/home/u1/codes
            ```

            * 默认执行第一个目标(在上面的文件中, 指`all`). 
            * `-C <目录>`: 指定跳转目录, 读取那里的Makefile. 
            * `M=<工作目录>`: 在读取上述Makefile, 跳转到`工作目录`, 继续读入Makefile. 
            * 注意上述选项后面接的路径都**必须是完整路径**. 
* git
    * 去除某个文件的历史提交记录: 
        1. `git filter-branch -f  --index-filter 'git rm -rf --cached --ignore-unmatch <目标文件相对项目根目录的路径>' HEAD`
        2. `git push origin --force --all`
* 库管理
    * `dpkg`
        * `-i`: 安装deb包. 
        * `--instdir=<安装路径>`: 
        * `dpkg-query -l`: 列出已安装包. 
        * `-P`: 卸载包. 

* 其他
    * `truncate`: 用于将文件缩小或扩展到指定的大小. 
        * 用来清除日志文件中的内容: `truncate -s 0 /var/log/yum.log`
        * 扩展文件: `truncate -s +200k file.txt`
    * 打印ansi彩色字体
        * `echo -e "\033[33m彩色\033[0m"`
    * 设置UTC时间
        * `sudo cp /usr/share/zoneinfo/UTC /etc/localtime`, 之后执行`date`命令可看到效果. 


# 设置
* sudo
    * 运行`visudo`(将会编辑`/etc/sudoers`)
    * 设置sudo无需密码
    > 找到`%admin ALL=(ALL) ALL`和`%sudo ALL=(ALL) ALL`, 改为`%admin ALL=(ALL) NOPASSWD: ALL`和`%sudo ALL=(ALL) NOPASSWD: ALL`. 
    * 添加sudo用户
    > 添加一行: `test ALL=(ALL) ALL`, `test`为用户名
