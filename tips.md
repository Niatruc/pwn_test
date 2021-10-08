**参考**<br>
[https://github.com/Naetw/CTF-pwn-tips](https://github.com/Naetw/CTF-pwn-tips)

查看系统的libc版本:
```sh
    ldd --version
```
内存hack(读写其他进程的内存):
通过读写/proc/<pid>/mem: [https://medium.com/@holdengrissett/linux-101-how-to-hack-your-process-memory-2514a3d0778d](https://medium.com/@holdengrissett/linux-101-how-to-hack-your-process-memory-2514a3d0778d)

# 可导致栈溢出的代码
假设有`char buf[40]`, `signed int num`, `char buf2[60]`
1. `scanf("%s", buf)`, 无边界检查, 可溢出.
2. `scanf("%40s", buf)`, 接收40字节后, 还会紧接着放一个NULL字节, 因此有`一字节溢出`.
3. `scanf("%d", &num)`
    * 配合`alloca(num)`: 该函数在栈上开辟空间, 其中有条指令`sub esp, eax`. 赋予`num`负数值, 将可覆盖栈帧.
    * 若代码只检查`num`的上限, 可赋予其负数值, 进而可能得到覆盖其他位置的能力.
4. `gets(buf)`: 无边界检查, 可溢出.
5. `fgets(buf, 40, stdin)`: **只接受39个字符, 末尾置NULL. 所以不能利用.**
6. `read(stdin, buf, 40)`及`fread(buf, 1, 40, stdin)`: 接受40个字符(没有附加NULL). 可利用它来泄漏一些信息, 比如canary. 有printf或puts时, 它们会一直打印到遇到NULL时. 如下, 则打印40个'A'和'\xcd\xe1\xff\xff\xff\x7f'.

    ```
    0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
    0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
    0x7fffffffdd20: 0x4141414141414141      0x00007fffffffe1cd
    ```
7. `strcpy(buf, buf2)`: 溢出
8. `strncpy(buf, buf2, 40)` 和 `memcpy(buf, buf2, 40)`: 拷贝40字节, 且结尾不放NULL. 可泄漏.
9. `strcat(buf, buf2)`: 在buf字符串的末尾拼接buf2字符串. 有溢出. 会放一个NULL在结尾, 可导致`one-byte-overflow`. 在某些地方可用这一个NULL来改变栈或堆地址.
10. `strncat(buf, buf2, n)`: 与strcat差不多, 只是多了大小限制. 可pwn. 例子: [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)

# 用gdb找字符串
在SSP(Stack Smashing Protector)问题中, 需要找到`argv[0]`和输入缓存之间的下标.

**gdb**:

```sh
(gdb) p/x (char **)environ
$9 = 0x7fffffffde38
(gdb) x/gx 0x7fffffffde38-0x10
0x7fffffffde28: 0x00007fffffffe1cd
(gdb) x/s 0x00007fffffffe1cd
0x7fffffffe1cd: "/home/naetw/CTF/seccon2016/check/checker"
```

**gdb-peda**:

```sh
gdb-peda$ searchmem "/home/naetw/CTF/seccon2016/check/checker"
Searching for '/home/naetw/CTF/seccon2016/check/checker' in: None ranges
Found 3 results, display max 3 items:
[stack] : 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffed7c ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffefcf ("/home/naetw/CTF/seccon2016/check/checker")
gdb-peda$ searchmem 0x7fffffffe1cd
Searching for '0x7fffffffe1cd' in: None ranges
Found 2 results, display max 2 items:
   libc : 0x7ffff7dd33b8 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffde28 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
```
# 为一个二进制程序开启一个服务

```sh
    ncat -vc ./binary -kl 127.0.0.1 $port
```
两种方法指定库:
```sh
    ncat -vc 'LD_PRELOAD=/path/to/libc.so ./binary' -kl 127.0.0.1 $port
    ncat -vc 'LD_LIBRARY_PATH=/path/of/libc.so ./binary' -kl 127.0.0.1 $port
```
之后连接到该服务:
```sh
    nc localhost $port
```

# 在libc中找函数
```sh
$ readelf -s libc-2.19.so | grep system@
    620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
   1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```
```py
from pwn import *

libc = ELF('libc.so')
system_off = libc.symbols['system']

```
# 在库中找到'/bin/sh'或'sh'
记得找到后还要加上库在进程中的加载地址

```sh
objdump -s libc.so | less then search 'sh'
# 或
strings -tx libc.so | grep /bin/sh
```

```py
from pwn import *

libc = ELF('libc.so')
...
sh = base + next(libc.search('sh\x00'))
binsh = base + next(libc.search('/bin/sh\x00'))
```

# 泄露栈地址
条件:
* 已泄露libc基址
* 可泄露任意地址的数据

libc中有一个`environ`符号, 其与main函数的三参`envp`的值相同, 而这个`envp`在栈上, 故我们可以泄露它.

```sh
(gdb) list 1
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       extern char **environ;
5
6       int main(int argc, char **argv, char **envp)
7       {
8           return 0;
9       }
(gdb) x/gx 0x7ffff7a0e000 + 0x3c5f38
0x7ffff7dd3f38 <environ>:       0x00007fffffffe230
(gdb) p/x (char **)envp
$12 = 0x7fffffffe230
```

`0x7ffff7a0e000`是libc基址, `0x3c5f38`是`environ`在libc中的地址.

# gdb中遇到fork
如果调试的程序中有fork, 如下决定gdb将跟随哪个进程. gdb中默认设定是parent, gdb-peda则是child.

```sh
set follow-fork-mode parent

set follow-fork-mode child
```

`set detach-on-fork off`: 则可设置每个fork的进程
`info inferiors`: 列出fork进程号
`inferior <fork号>`: 切到对应的fork进程

# 可预测的RNG(随机数生成器)
有时程序会有RNG生成的数字来指定地址, 如果RNG可预测, 这时可用python的`ctypes`调用DLL来模拟RNG, 得到一样的随机数. 假设目标程序如下:
```c
srand(time(NULL));
while(addr <= 0x10000){
    addr = rand() & 0xfffff000;
}
secret = mmap(addr,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,-1,0); // mmap在addr处分配内存
if(secret == -1){
    puts("mmap error");
    exit(0);
}
```

如下可得到`addr`:
```py
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/path/to/dll')
LIBC.srand(LIBC.time(0))
addr = LIBC.rand() & 0xfffff000
```

# 使栈可执行
如果没有`system`或`execve`的rop可用, 则可考虑通过rop链让栈可执行代码的方法.

## 利用_dl_make_stack_executable
`_dl_make_stack_executable`函数调用了`mprotect`, 这个函数原型是`int mprotect(const void *start, size_t len, int prot)`, `prot`取值的每个二进制位的含义是`PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC`, 因此将该值设为7可让某段内存获得读写执行权限.

引自:[https://quentinmeffre.fr/pwn/2017/01/26/ret_to_stack.html](https://quentinmeffre.fr/pwn/2017/01/26/ret_to_stack.html): 传给`_dl_make_stack_executable`函数的参数为`__libc_stack_end`.

```x86asm
mov    rsi,QWORD PTR [rip+0x23a731]        # 6ba118 <_dl_pagesize>
push   rbx
mov    rbx,rdi
mov    rdx,QWORD PTR [rdi]
mov    rdi,rsi
neg    rdi
and    rdi,rdx
cmp    rdx,QWORD PTR [rip+0x238ff2]        # 6b89f0 <__libc_stack_end>
jne    47fa20 <_dl_make_stack_executable+0x40>
mov    edx,DWORD PTR [rip+0x23942a]        # 6b8e30 <__stack_prot>
call   44a310 <__mprotect>
test   eax,eax
jne    47fa30 <_dl_make_stack_executable+0x50>
mov    QWORD PTR [rbx],0x0
or     DWORD PTR [rip+0x23a6eb],0x1        # 6ba108 <_dl_stack_flags>
pop    rbx
ret    
```

载荷的构成:
* 填充<br>
* 设置`__stack_prot`为7 <br>
* 设置`RDI`为`__libc_stack_end` <br>
* 执行函数`_dl_make_stack_executable` <br>
* push shellcode<br>

寻找`__libc_stack_end`和`__stack_prot`: <br>
```sh
$ objdump -D a.out | grep "__libc_stack_end"
$ objdump -D a.out | grep "__stack_prot"
```

一个例子:
```sh
# padding

# pop rsi ; ret
# @ __stack_prot
# pop rax ; ret
# 7
# mov QWORD PTR [rsi], rax ; ret    # 将__stack_prot设为7

# pop rdi ; ret
# @ __libc_stack_end
# @ _dl_make_stack_executable

# push rsp ; ret    # 因为此时rsp指向shellcode, 故将rsp的值作为下一个返回地址
# shellcode: 比如execve("/bin/sh", ["/bin/sh"], NULL)的机器码
```

# one-gadget-RCE(remote code execution)
`one-gadget`一般是`execve("/bin/sh",argv,envp)`这样一行代码. 用于替换`system`获取shell的方法, 尤其是当不能构造它的参数时. 只要劫持`.got.plt`表让某个函数跳到`one-gadget`即可. **libc中就有许多`one-gadget`**. 不过使用时有限制条件, 通常是要限制某些寄存器或地址为某值.<br>
可以使用一个有用的工具: (one-gadget)[https://github.com/david942j/one_gadget]
```sh
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
#
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL
#
# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

```

**条件**<br>
* 已知libc基址
* 可写任意地址

# 劫持钩子函数
**条件**<br>
* 已获取libc基址
* 可写任意地址
* 程序有调用`malloc`, `free`或`realloc`

GNU C提供类似`__malloc_hook`和`__free_hook`的钩子函数变量来改变malloc中的行为, 以助于调试. 比如`__libc_free`函数, 其中就有检查`__free_hook`, 如果不是NULL, 就会调用它. 使`free`的堆块中的内容为"/bin/sh\00", 然后修改`__free_hook`使它指向`system`函数. 
```c
void (*hook) (void *, const void *) = atomic_forced_read (__free_hook);
if (__builtin_expect (hook != NULL, 0))
{
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
}
```

# 通过printf来触发malloc和free
* 大多时候触发`malloc`和`free`的最小大小是65537
* 如果程序有格式化字符串漏洞且程序在`printf(buf)`后结束, 则可以通过`one-gadget`劫持`__malloc_hook` 或 `__free_hook` 。

# 利用execveat函数拿到shell
这个函数的原型如下, 它和`execve`差不多, 只是多了“如果pathname是绝对路径, 则忽略dirfd”. 因此可将`pathname`指向`"/bin/sh"`, 将`argv`, `envp`及`flags`设为0.
```c
int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[],
             int flags);
```

# Ropgadgets
引自[https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf](https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf)

Ropgadgets主要有如下这些不同用途的类别:
* 将栈上的数值载入寄存器
    * pop eax; ret;
* 从内存中读取数据到寄存器
    * mov ecx,[eax]; ret
* 将数值存入内存
    * mov [eax],ecx; ret
* 算术操作: 加, 减, 乘, 异或, 与
    * add eax,0x0b; ret (will add 0x0b to eax)
    * xor edx,edx;ret (will zero out edx)
* 系统调用
    * int 0x80; ret
    * call gs:[0x10]; ret

避免使用leave/ret(等同于pop ebp; ret), 因为会把栈弄乱

## ROPgadgets 工具
**pwntools的rop**

[https://docs.pwntools.com/en/stable/rop/rop.html](https://docs.pwntools.com/en/stable/rop/rop.html)

```py
# 新建ROP对象
rop = ROP(binary)

# 插入字符串
rop.raw('AAAAAAAA')
rop.generatePadding(0, 72) # 插入生成的字符串, 长72

# 解析符号的地址
rop.resolve('<符号名>')

# 插入对read函数的调用, 后面的列表为参数
ret2stack_rop.call('read', [4,5,6])
ret2stack_rop.read([4,5,6])     # 另一种写法

# 利用'pop rsp; ret'或‘leave; ret’实现清除当前函数栈帧并跳转
rop.migrate(base_stage)

# 
rop.find_gadget(['pop rax'])

# 
ELF.from_assembly(assembly)

# 获取构建的rop链
print(enhex(rop.chain()))

```

## ROPgadget
ROPgadget --binary <可执行文件> --only "mov|ret"

配合`less`搜索的正则表达式:

```sh
# 搜索mov到内存的指令, 如mov qword ptr [rdi], rsi
\: mov [^;]*\[[^;]*, r
```
