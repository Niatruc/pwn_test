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


# 泄漏栈地址
## 利用**envp参数
条件:
1. 已泄漏libc基址
2. 能泄漏任意地址内容
