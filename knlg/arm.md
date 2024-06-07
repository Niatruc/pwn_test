* 参考
    * [arm 体系架构及其工作原理图_arm架构详解](https://cloud.tencent.com/developer/article/2151966)
    * [Android逆向基础](https://github.com/JnuSimba/AndroidSecNotes/tree/master/Android%E9%80%86%E5%90%91%E5%9F%BA%E7%A1%80)
    * https://developer.arm.com/documentation/dui0802/b/A32-and-T32-Instructions/
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