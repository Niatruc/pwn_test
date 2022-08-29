# 进程
* api
    * `fork`: 创建子进程, 其从调用`fork`之后的地方开始执行.     
        * 返回值
            * 负值: 创建子进程失败. 
            * 零: 返回到新创建的子进程. (即若返回值为0, 表面此时在子进程中)
            * 正值: 返回父进程. 该值包含新创建的子进程的进程ID. (即若返回值大于0, 表面此时在父进程中)
    * `signal(int sig, void (*func)(int))`: 设置`func`函数, 来等待`sig`信号
        * 一些常用信号
            |信号常量|信号含义|
            |-|-|
            |SIGABRT|	(Signal Abort) 程序异常终止. |
            |SIGFPE|	(Signal Floating-Point Exception) 算术运算出错，如除数为 0 或溢出（不一定是浮点运算）. |
            |SIGILL|	(Signal Illegal Instruction) 非法函数映象，如非法指令，通常是由于代码中的某个变体或者尝试执行数据导致的. |
            |SIGINT|	(Signal Interrupt) 中断信号，如 ctrl-C，通常由用户生成. |
            |SIGSEGV|	(Signal Segmentation Violation) 非法访问存储器，如访问不存在的内存单元. |
            |SIGTERM|	(Signal Terminate) 发送给本程序的终止请求信号. |
    * `pid_t waitpid(pid_t pid,int * status,int options)`: 暂停进程, 等待信号到来或pid子进程结束. 
    * `int execvp(const char *file ,char * const argv [])`: 执行可执行文件. 成功则不返回, 否则返回-1. 