# Linux程序的堆漏洞利用方法
1. 利用堆管理系统中的一些赋值操作, 实现对任意地址的改写.
    * 利用堆合并时的赋值操作(BK->fd = FD)改变任意地址值(如, 保存堆块地址的地址).
        * [unsafe unlink 图解](./unsafe_unlink/笔记.md)
        * [double free 图解](./double_free/笔记.md)
    * 利用从bins链取块或将块插入bins链后的链接操作改变任意地址值.
        * [unsorted bin attack 图解](./unsorted_bin_attack/笔记.md)
        * [large bin attack 图解](./large_bin_attack/笔记.md)
2. 在bin链中插入指向任意可写地址(如栈段, bss等)的假块, 再结合malloc获得对假块区域的写权限.
    * 改写单链bin(fastbin, tcache)上的块的bk或fd字段使之指向任意可写地址.
        * [fastbin dup 图解](./fastbin_dup/笔记.md)
        * [house of lore 图解](./house/笔记.md#house-of-lore)
        * [house of botcake 图解](./house/笔记.md#house-of-botcake)
    * 将任意可写地址作为free的参数.
        * [house of spirit 图解](./house/笔记.md#house-of-spirit)
3. 篡改top块, 使得malloc返回任意可写地址.
    * [house of force 图解](./house/笔记.md#house-of-force): 篡改top块的大小
    * [house of einherjar 图解](./house/笔记.md#house-of-einherjar): 通过free时的合并操作引起top块的起始位置的改变.
4. 利用free时对arena的元数据malloc_state中的fastbinY数组等的修改操作, 将目标位置的值改为free的块的地址.
    * [house of mind fastbin 图解](./house/笔记.md#house-of-mind-fastbin)

# 其他二进制漏洞
- [栈溢出](./stack_overflow/栈溢出笔记.md#ROP)
- [格式化字符串漏洞](./tips.md#格式化字符串漏洞)

# 经验-技巧
- [用ida调试pwn题](./pwn分析环境搭建.md#ctf-pwn题目程序调试)
- [可导致栈溢出的代码](./tips.md#可导致栈溢出的代码)
- [用gdb找字符串](./tips.md#用gdb找字符串)
- [为一个二进制程序开启一个服务](./tips.md#为一个二进制程序开启一个服务)
- [在libc中找函数](./tips.md#在libc中找函数)
- [在库中找到'/bin/sh'或'sh'](./tips.md#在库中找到'/bin/sh'或'sh')
- [泄露栈地址](./tips.md#泄露栈地址)
- [gdb中遇到fork](./tips.md#gdb中遇到fork)
- [预测随机数](./tips.md#预测随机数)
- [使栈可执行](./tips.md#使栈可执行)
- [one-gadget-RCE](./tips.md#one-gadget-RCE)
- [劫持钩子函数](./tips.md#劫持钩子函数)
- [通过printf来触发malloc和free](./tips.md#通过printf来触发malloc和free)
- [利用execveat函数拿到shell](./tips.md#利用execveat函数拿到shell)
- [Ropgadgets用途及工具](./tips.md#Ropgadgets)

# ctf pwn题预备工作
- [ctf pwn题目程序调试](./pwn分析环境搭建.md#ctf-pwn题目程序调试)
    - [使用python的subprocess模块发送和接收数据](./pwn分析环境搭建.md#方法一:-使用python的subprocess模块)
    - [通过管道发送和接收数据](./pwn分析环境搭建.md#方法二:-使用管道)

- [ida](./ida笔记.md)
    - [用pycharm调试ida插件](./ida笔记.md#用pycharm调试ida插件)

- [用vscode调试C++源码](./pwn分析环境搭建.md#用vscode调试C++源码)
    - [配置](./pwn分析环境搭建.md#配置)
    - [调试](./pwn分析环境搭建.md#调试)
    - [搭建远程调试环境(vscode+gdbserver)](./pwn分析环境搭建.md#远程调试虚拟机中的程序)
- [其他](./pwn分析环境搭建.md#其他)
    - [下载不同版本的libc等库文件](./pwn分析环境搭建.md#下载不同版本的libc等库文件)
    - [指定.so文件路径](./pwn分析环境搭建.md#so文件路径)
    - [fcntl](./pwn分析环境搭建.md#fcntl)

# 一些预备知识
- [堆中的元数据](./堆知识笔记.md#堆中的元数据)
- [libc堆管理中的'向前'和'向后'](./堆知识笔记.md#libc堆管理中的'向前'和'向后')
    - [向后合并](./堆知识笔记.md#向后合并)
    - [向前合并](./堆知识笔记.md#向前合并)
- [top块](./堆知识笔记.md#top块)
- [fastbinsY数组存储fastbins的规则](./堆知识笔记.md#fastbinsY数组存储fastbins的规则)
- [large bins](./堆知识笔记.md#large-bins)
- [bin链出入顺序](./堆知识笔记.md#bin链出入顺序)
- [保护机制](./堆知识笔记.md#保护机制)
    - [RELRO](./堆知识笔记.md#RELRO)
    - [PIE(position-independent executable)](./堆知识笔记.md#PIE(position-independent-executable))
    - [Canary](./堆知识笔记.md#Canary)

# Windows内核
- [NT驱动框架](./knlg/win_krnl.md#NT驱动框架)
    - [驱动运行流程](./knlg/win_krnl.md#驱动运行流程)