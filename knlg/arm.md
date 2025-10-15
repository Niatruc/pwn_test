* 参考
    * [arm 体系架构及其工作原理图_arm架构详解](https://cloud.tencent.com/developer/article/2151966)
    * [深入了解ARM版本系列及家族成员梳理大全（超详细）](https://www.bilibili.com/opus/642668192949338120)
    * [Android逆向基础](https://github.com/JnuSimba/AndroidSecNotes/tree/master/Android%E9%80%86%E5%90%91%E5%9F%BA%E7%A1%80)
    * [A32 and T32 Instructions](https://developer.arm.com/documentation/dui0802/b/A32-and-T32-Instructions/)
    * [移动安全之Android逆向系列：ARM汇编&IDA动态分析源码](https://forum.butian.net/share/707)
    * [arm64架构分析](https://github.com/hardenedlinux/embedded-iot_profile/blob/master/docs/arm64/arm64%E6%9E%B6%E6%9E%84%E5%88%86%E6%9E%90.md)
* arm架构与处理器家族: 
    * `ARMv1`: `ARM1`
    * `ARMv2`: `ARM2`, `ARM3`
    * `ARMv3`: `ARM6`, `ARM7`; **从这个版本可配置大小端序(默认小端序)**
    * `ARMv4`: `StrongARM`, `ARM7TDMI`, `ARM9TDMI`
    * `ARMv5`: `ARM7EJ`, `ARM9E`, `ARM10E`, `XScale`
    * `ARMv6`: `ARM11`, `ARM Cortex-M`
    * `ARMv7`: `ARM Cortex-A`, `ARM Cortex-M`, `ARM Cortex-R`
    * `ARMv8`: `Cortex-A35`, `Cortex-A50`系列, `Cortex-A70`系列, `Cortex-X1`
    * `ARMv9`: `Cortex-A510`, `Cortex-A710`, `Cortex-A715`, `Cortex-X2`, `Cortex-X3`, `ARM Neoverse N2`
* 模式: 在任何时刻, CPU只可处于某一种模式, 但可由于外部事件(中断)或编程方式进行模式切换. 
    * 用户模式
        * 仅非特权模式. 
    * 系统模式
        * 仅无需例外进入的特权模式. 仅以执行明确写入CPSR的模式位的指令进入. 
    * Supervisor (svc) 模式
        * 在CPU被重置或者SWI指令被执行时进入的特权模式. 
    * Abort 模式
        * 预读取中断或数据中断异常发生时进入的特权模式. 
    * 未定义模式
        * 未定义指令异常发生时进入的特权模式. 
    * 干预模式
        * 处理器接受一条IRQ干预时进入的特权模式. 
    * 快速干预模式
        * 处理器接受一条IRQ干预时进入的特权模式. 
    * Hyp 模式
        * `armv7a`为`cortex-A15`处理器提供硬件虚拟化引进的管理模式. 
* 安装交叉编译器
    * `sudo apt-get install gcc-arm-linux-gnueabihf`
# 寄存器
* arm
    * 未备份寄存器(`r0` ~ `r7`)
        * `r0` ~ `r3:` 传参. `r0`常用于存结果. 
        * `r4` ~ `r6`: 
            * 是`callee-save`寄存器(即被使用前要先保存值)
            * 常用于保存局部变量
        * `r7`
            * 保存栈底地址(相当于x86的bp寄存器)(thumb模式下)
            * 保存系统调用号
    * 备份寄存器(`r8` ~ `r14`)
        * `r8`, `r10`, `r11`: 通用寄存器
        * `r9`: 保留
        * `r10`(`SL`): `callee-save`寄存器, Stack Limit(`sl`). 
        * `r11`(`FP`): `callee-save`寄存器,  帧指针`fp`(Flame Pointer)(相当于x86的`ebp`)
        * `r12`(`IP`(`intra-procedure scratch`)): 
        * `r13`: 堆栈指针`SP`, 指向栈顶
        * `r14`: `LR`寄存器(linked register), 存**返回地址**
        * `r15`: 程序计数器`PC`
* aarch64
    * `x0` ~ `x7`: 传递子程序的参数和返回值, 多余的参数用堆栈传递, 64位的返回结果保存在`x0`中. 
    * `x8`: 间接结果寄存器，用于保存子程序返回地址, 尽量不要使用. 
    * `x9` ~ `x15`: 临时寄存器, 也叫可变寄存器. 
    * `x16` ~ `x17`: 子程序内部调用寄存器(`IP0`, `IP1`), 尽量不要使用. 
    * `x18`: 平台寄存器(`PR`), 它的使用与平台相关, 尽量不要使用. 
    * `x19` ~ `x28`: 临时寄存器. (`callee-save`)
    * `x29`(`FP`): 帧指针寄存器. (`callee-save`)
    * `x30`(`LR`): 链接寄存器. 
    * `SP`: 堆栈指针寄存器. 
    * `PC`: 计数器. 
* `WZR`, `XZR`: 零寄存器
# 指令
* 特性
    * 每个指令前头使用一个4位的条件编码, 表示该指令是否为有条件式地执行
* 基本格式: `<opcode>{<cond>}{S}  <Rd>,<Rn>{,<opcode2}`
    * `opcode`: 指令助记符,如`LDR`, `STR`等
    * `cond`: 执行条件, 如`EQ`, `NE`等
    * `S`: 是否影响`CPSR`寄存器的值, 若有则影响
    * `Rd`: 目标寄存器
    * `Rn`: 第一个操作数的寄存器
    * `opcode2`: 第二个操作数
* 存储器访问指令
    * `PUSH`
        * `PUSH {R4-R6,LR}`: 在arm 32位程序的函数开头通常能看到类似这样的指令, 暂存上下文环境. 
    * `POP`
        * `POP {R4-R6,PC}`: 与上面的push指令相对应, 常出现于结尾. 
            * 注: **arm 32位没有`RET`指令, 在结尾会直接修改PC寄存器, 或用`B`指令跳转.** 
    * `LDR`(load register)(内存到寄存器)(从右往左): 加载一个字(word, 通常为32位)的数据到一个指定的寄存器
        * `LDR R8, [R9, #4]`: 将`R9 + 0x4`的运算结果指向的内存数据存到`R8`
        * `LDR R8, [R9], #4`: 将`R9`指向的内存数据加上4, 将所得地址指向的内容存到`R8`
    * `LDM`(load multiple registers)(内存到寄存器)(从左往右): 加载多个字的数据到多个指定的寄存器
        * `LDM R0!, {R1-R3}`: 将R0指向的存储单元的数据依次加载到R1,R2,R3寄存器
            * `!`的作用是每次从R0读一次值, R0自增4(个字节). 如上指令, R0最后会自增12. 
    * `STR`(store register)(寄存器到内存)(从左往右)
        * `STR R8, [R9, #4]`: 将`R8`的值写入`R9 + 0x4`的运算结果指向的内存地址处
    * `STP`: `P`可理解为pair. 可同时操作两个寄存器
        * `STP x29, x30, [SP, #0x10]`  ; 将 `x29`, `x30` 的值存入 `sp` 偏移 16 个字节的位置. **在函数的开头通常都会有这行指令**
    * `STM`(store multiple registers)(寄存器到内存)(从右往左): 可用于保存现场
        * `STM R0!, {R1-R3}`: 将R1-R3的数据存储到R0指向的地址上
    * `SWP`
        * `SWP R1, R2 [R0]`: 读取R0指向的内容到R1中, 并将R2的内容写入到该内存单元中
* 分支跳转指令
    * `B <地址>`: 无条件跳转. 
    * `BR <地址>`: 无条件跳转(至寄存器). 
    * `BL <地址>`: 带链接的跳转. 用于函数调用. 
    * `CB`: 将寄存器值与立即数比较后再进行跳转. 
        * `CBNZ <Wt>, <label>`: `<Wt>`寄存器值不为0则跳转至`<label>`
    * `TB`: 测试位后后再进行跳转. 
        * `TBZ <Wt>, #<imm>, <label>`: 若`<Wt>`与`#<imm>`相与的结果为0则跳转到`<label>`