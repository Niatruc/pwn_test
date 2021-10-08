
linux系统调用号:
 /usr/include/asm/unistd.h

# fork
执行fork后, 产生子进程,其与主进程几乎一样, 并从fork的下一句开始执行.

1. 在父进程中，fork返回新创建子进程的进程ID；
2. 在子进程中，fork返回0；
3. 如果出现错误，fork返回一个负值；