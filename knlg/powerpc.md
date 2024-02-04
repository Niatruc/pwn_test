* 参考
    * 参考手册: https://math-atlas.sourceforge.net/devel/assembly/ppc_isa.pdf
    * https://blog.csdn.net/whatday/article/details/87253637
    * http://rootkiter.com/2017/03/08/PowerPC_Study.html
    * https://www.eefocus.com/article/400490.html
    * 助记符参考:
        * https://www.ibm.com/docs/en/aix/7.1?topic=reference-appendix-f-powerpc-instructions
        * http://class.ece.iastate.edu/arun/CprE281_F05/lab/labw10b/Labw10b_Files/PowerPC%20Assembly%20Quick%20Reference.htm

* 对齐: 4字节对齐. 分析中发现, 数据区中的字符串也会以4字节对齐, 对齐部分填0. 

* 通用寄存器(gpr)
    * `r0`: 在函数开始(function prologs)时使用. 
    * `r1`: 堆栈指针, 相当于ia32架构中的esp寄存器, idapro把这个寄存器反汇编标识为sp. 
    * `r2`: 内容表(toc)指针, idapro把这个寄存器反汇编标识为rtoc. 系统调用时, 它包含系统调用号. 
    * `r3`: 作为第一个参数和返回值. 
    * `r4-r10`: 函数或系统调用开始的参数. 
    * `r11`: 用在指针的调用和当作一些语言的环境指针. 
    * `r12`: 它用在异常处理和glink(动态连接器)代码. 
    * `r13`: 保留作为系统线程ID. 
    * `r14-r31`:作为本地变量, 非易失性. 
* 浮点寄存器(fpr)
* 专用寄存器(spr)
    * `lr`: 链接寄存器, 用来存放函数调用结束时的返回地址. 
    * `ctr`: 计数寄存器, 用来当作循环计数器, 会**随特定转移操作而递减**. 
    * `xer`: 定点异常寄存器, 存放整数运算操作的**进位以及溢出信息**. 
    * `msr`: 机器状态寄存器, 用来配置微处理器的设定. 
    * `sr`: 段寄存器. 
    * `cr`: 条件寄存器, 它分成8个4位字段, cr0-cr7, 它反映了某个算法操作的结果并且提供条件分支的机制. 
* 指令地址寄存器(IAR): 即程序计数器, 存放当前指令的地址. 是一个伪寄存器, 只能通过跳转链接指令使用. 
* 处理器版本寄存器(pvr): 一个 32 位只读寄存器, 标识处理器的版本和修订级别. 

# 指令
* `s`: store
    * `stb  rS, d(rA)`: `m[rA + d] = rS的第一个字节`
    * `stw r3, 0x0(sp)`: 将r3的值放到栈顶(左至右)
    * `stwu rS, d(rA)`: 偏移地址寻址, `[d + rA] = rS`
* `s`: shift
    * `slwi rA, rS, value`: `rA = (rS << value)`
    * `srwi rA, rS, value`: `rA = (rS >> value)`
* `l`: load
    * `li rd,imm`: `rd = imm`, 寄存器赋值(右至左)
    * `lis rd,imm`: `rd = imm << 16`, 寄存器高位赋值
    * `lwz rD, d(rA)`: `rD = M[rA + d]`. (Load Word and Zero)
    * `lwzu rD, d(rA)`: `rD = M[rA + d]`. (Load Word and Zero with Update)
    * `lbz rD, d(rA)`: `rD = m[rA + d]`, 将一个字节和0赋给rD. 
    * `lbzx rD, rA, rB`: `rD = m[rA + rB]`
* `r`: right
* `l`: left; logical
* `w`: word
* `u`: update
* `m`: move
    * `mr rA, rS`: `rA = rS`
    * `mfmsr rA`: 将msr寄存器值移到rA
    * `mfspr`: 
    * `mfsr`: 
    * `mflr`: 
    * `mfctr`: 
* `f`: from; field
* `t`: to; than; trap
    * trap指令: 用于测试条件, 若条件符合, 则会调用trap的处理器. 
* `i`: immediate
* `h`: half word
* `z`: zero
* `b`: blanch (跳转指令)
    * `bl <addr>`: 跳转到地址. bl指令的下一条指令的地址会被记录到lr寄存器. 
    * `blr`: 将程序计数器的值设为链接寄存器的值(相当于`ret`)
    * `bdz <addr>`: ctr寄存器减1, 若为0则跳转. 
    * `bne <addr>`: 若不相等则跳转(根据cr0寄存器判断). 
* `n`: and
* `cmp`: compare
    * `cmpw cr7, rA, rB`: `cr7 = rA - rB`
* `sub`: substract
* `clr`: clear
    * `clrlwi Rx, Ry, 16`: 把32位寄存器Ry的高16位清空, 结果存放于Rx. 
    * `clrrwi Rx, Ry, 16`: 同上, 但清空低16位. 
* `add`: 加法
    * `add rD, rA, rB`: `rD = rA + rB`
    * `addi rD, rA, v`: `rD = rA + v`, 加上立即数
* ``: 减法
    * `subf r0, r0, r8`: `r0 = r8-r0` (substract from)
* `or`: 或运算
    * `ori rA, rS, value`: `rA = rS | value`
    * `oris  rA, rS, value`: `rA = rS | (value << 16)`
    * ``: 
* `sync`: 确保该指令前的所有指令已完成, 然后完成该指令, 再执行后面的指令. 

# 函数
* 通常能在开头看到如下代码: 
    ```x86asm
        mflr r0 ; 保存返回地址到r0
        stwu r1, back_chain(r1) ; back_chain的值为负数, r1是栈顶指针, 所以这里应该是开辟用于保存局部变量的栈空间. 
    ```

# 代码
```x86asm
    ; 加载立即数0x12345678到寄存器r9
    lis r9, 0x1234
    ori r9, r9, 0x5678

    ; 加载变量a的地址(立即数)到r9
    lis r9, a@ha
    addi r9, r9, a@l
```

# 编译
* 安装gcc: `apt install gcc-powerpc-linux-gnu binutils-powerpc-linux-gnu`
* 编译: 使用`powerpc-linux-gnu-gcc`, 用法同gcc. 