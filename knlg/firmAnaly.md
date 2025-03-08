* 参考
    * [Firmware Analysis](https://book.hacktricks.xyz/v/cn/hardware-physical-access/firmware-analysis)
    * [一文搞懂Uboot代码结构](https://juejin.cn/post/7087465249137246245#heading-54)
    * [一文搞懂嵌入式uboot、kernel、文件系统的关系](https://www.cnblogs.com/schips/p/13129047.html)
    * [Booting AArch64 Linux](https://docs.kernel.org/arch/arm64/booting.html)
    * [Arm64下Linux内核Image头的格式](https://blog.csdn.net/Roland_Sun/article/details/105144372)
    * [\[原创\]看雪2018峰会回顾_智能设备漏洞挖掘中几个突破点(内有十种固件提取方法和首次公开uboot提取固件方法) ](https://bbs.kanxue.com/thread-230095.htm)

* 存储介质
    * NOR闪存
        * Intel于1988年开发
        * 可以通过CPU直接寻址
        * 芯片内执行（XIP ，eXecute In Place），这样应用程序可以直接在Flash闪存内运行，不必再把代码读到系统RAM中
        * NOR的读速度比NAND稍快一些
        * 占据了容量为1～16MB闪存市场的大部分，适用于存储代码。
    * NAND闪存
        * 1989年，东芝公司发表了NAND Flash 结构
        * 提供极高的单元密度，可以达到高存储密度，并且写入和擦除的速度也很快
        * NAND的写入速度比NOR快很多。
        * 用在8～128MB的产品当中，适用于数据存储。
        * 使用NAND器件时，必须先写入驱动程序，才能继续执行其他操作。