* 参考
    * [arm 体系架构及其工作原理图_arm架构详解](https://cloud.tencent.com/developer/article/2151966)
    * [Android逆向基础](https://github.com/JnuSimba/AndroidSecNotes/tree/master/Android%E9%80%86%E5%90%91%E5%9F%BA%E7%A1%80)
    * https://developer.arm.com/documentation/dui0802/b/A32-and-T32-Instructions/

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
# 指令
* 特性
    * 每个指令前头使用一个4位的条件编码， 表示该指令是否为有条件式地执行
# 寄存器
* 未备份寄存器(r0 ~ r7)
    * r0 ~ r3: 传参. r0常用于存结果. 
    * r4 ~ r6: 
        * 是`callee-save`寄存器(即被使用前要先保存值)
        * 常用于保存局部变量
    * r7
        * 保存栈底地址(相当于x86的bp寄存器)(thumb模式下)
        * 保存系统调用号
* 备份寄存器(r8 ~ r14)
    * r8, r10, r11: 通用寄存器
    * r9: 保留
    * r10(SL): `callee-save`寄存器, Stack Limit(sl). 
    * r11(FP): `callee-save`寄存器,  帧指针fp(Flame Pointer)(相当于x86的`ebp`)
    * r12(IP(`intra-procedure scratch`)): 
    * r13: 堆栈指针sp, 指向栈顶
    * r14: LR寄存器(linked register), 存返回地址
    * r15: 程序计数器PC