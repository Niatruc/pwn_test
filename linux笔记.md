# 重要文件
linux系统调用号:
 /usr/include/asm/unistd.h

# 有用的工具
查看linux系统已安装的库
```sh
ldconfig -p
```

# KVM
[KVM](https://www.redhat.com/zh/topics/virtualization/what-is-KVM), 基于内核的虚拟机 Kernel-based Virtual Machine（KVM）

# fork
执行fork后, 产生子进程,其与主进程几乎一样, 并从fork的下一句开始执行.

1. 在父进程中，fork返回新创建子进程的进程ID；
2. 在子进程中，fork返回0；
3. 如果出现错误，fork返回一个负值；