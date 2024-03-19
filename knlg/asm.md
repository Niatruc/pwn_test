* 编译, 链接
    * 使用gcc: `gcc -o test test.S`, 源文件后缀名为`S`, 这样可以使gcc自动识别汇编程序中的c预处理命令, 包括头文件中的情况, 像`#include`, `#define` , `#ifdef`等. 
    * 使用as和ld: 
        > `as test.s –o test.o`
        > `ld test.o –o test `

* AT&T写法: 
    * 参考
        * [AT&T的汇编世界](https://zhuanlan.zhihu.com/p/54821702)
    * 寄存器命名: `%eax`
    * 源操作数在前, 目的操作数在后
    * 指令后缀表示操作的字节数: b(1), w(2), l(4), q(8)
    * 立即数要以`$`为开头: $8
    * 与Intel写法对应: 
        |Intel|AT&T|
        |-|-|
        |`mov al, bl`|`movb %bl, %al`|
        |`mov ax, bx`|`movw %bx, %ax`|
        |`mov eax, ebx`|`movl %ebx, %eax`|
        |`mov eax, dword ptr [ebx]`|`movl (%ebx), %eax`|
        |`mov eax, [ebx + 20h]`|`movl 0x20(%ebx), %eax`|
        |`add eax, [ebx + ecx * 2h]`|`addl (%ebx, %ecx, 0x2), %eax`|
        |`lea eax, [ebx + ecx]`|`leal (%ebx, %ecx), %eax`|
        |`sub eax, [ebx + ecx * 4h - 20h]`|`subl -0x20(%ebx, %ecx, 0x4), %eax`|
        |||
    * 标号: 用于跳转. 
        ```x86asm
            1:  cmp  $0, (%si)  
                je  1f         # 跳转到后面的1标示的地方, 也就是第6行
                movsb  
                stosb  
                jmp  1b        # 跳转到前面1表示的地方,  也就是第1行
            1:  jmp  1b        # 跳转到前面1表示的地方, 第6行, 其实就是个死循环
        ```
    * 汇编指示符: 以`.`开头. 
        * `.byte`
            ```x86asm
                after_BPB:
                CLI
                .byte 0x80,0xca # 在cli指令的下面接着放上0x80和0xca
            ```
        * `.word`: 与上面类似. 
        * `.file`: 告诉编译器准备开启一个新的逻辑文件. 后续版本不再支持. 
            * `.file "stage1.s"`
        * `.code`
            * `.code 16`: 告诉编译器生成16位的指令. 
        * `.fill <repeat>, <size>, <value>`: 生成`size`个字节的`repeat`个副本
        
