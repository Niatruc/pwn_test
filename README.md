# 各堆漏洞原理概述
1. 利用堆合并时的赋值操作(BK->fd = FD)改变特定地址(如, 保存堆块地址的地址).
    * [unsafe unlink 图解](./unsafe_unlink/笔记.md)
    * [double free 图解](./double_free/笔记.md)
2. 在bin链中插入指向任意可写地址(如栈段, bss等)的假块, 再结合malloc获得对假块区域的写权限.
    * 改写单链bin(fastbin, tcache)上的块的bk或fd字段使之指向任意可写地址.
        * [fastbin dup 图解](./fastbin_dup/笔记.md)
        * [house of lore 图解](./house/笔记.md#house-of-spirit)
        * [house of botcake 图解](./house/笔记.md#house-of-lore)
    * 将任意可写地址作为free的参数.
        * [house of spirit 图解](./house/笔记.md#house-of-force)
3. 篡改top块, 使得malloc返回任意可写地址.
    * [house of force 图解](./house/笔记.md#house-of-einherjar): 篡改top块的大小
    * [house of einherjar 图解](./house/笔记.md#house-of-botcake): 通过free时的合并操作引起top块的起始位置的改变.

