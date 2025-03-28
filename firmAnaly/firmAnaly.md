* 参考
    * [Firmware Analysis](https://book.hacktricks.xyz/v/cn/hardware-physical-access/firmware-analysis)
    * [一文搞懂Uboot代码结构](https://juejin.cn/post/7087465249137246245#heading-54)
    * [一文搞懂嵌入式uboot、kernel、文件系统的关系](https://www.cnblogs.com/schips/p/13129047.html)
    * [Booting AArch64 Linux](https://docs.kernel.org/arch/arm64/booting.html)
    * [Arm64下Linux内核Image头的格式](https://blog.csdn.net/Roland_Sun/article/details/105144372)
    * [\[原创\]看雪2018峰会回顾_智能设备漏洞挖掘中几个突破点(内有十种固件提取方法和首次公开uboot提取固件方法) ](https://bbs.kanxue.com/thread-230095.htm)
    * [嵌入式设备固件安全分析技术研究综述](http://cjc.ict.ac.cn/online/bfpub/yyc-2020818141436.pdf#page=8.09)

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

* 固件提取
    

# FirmAE
* 参考: [FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis阅读笔记](https://zhuanlan.zhihu.com/p/540725241)
# FACT
* 参考: https://fkie-cad.github.io/FACT_core/index.html
* 安装: 
    * 参考: [FACT installation](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.md)
    * 如果在miniconda环境下安装, 则修改`src/helperFunctions/install.py`中的`is_virtualenv`函数, 直接返回True. 
    * 安装uwsgi时出错提示`undefined reference to 'SSL_get_peer_certificate'`, 疑似与ssl版本, 且在conda环境下才会有此问题. 
        * 参考: https://github.com/unbit/uwsgi/issues/1516
            ```sh
                # 方法1: 
                conda config --add channels conda-forge
                conda install uwsgi

                # 方法2: 
                pip install pyuwsgi
            ```
* 任务
    * 软件识别
        * 识别OS
        * 识别程序
        * 识别版本
        * 识别引导时启动的服务
        * 识别CVE
    * 寻找登录凭证(硬编码口令)
    * 识别加密密钥: 私钥, 证书
    * 识别CPU架构(仿真和反汇编时用到)
    * 检查可执行文件是否可用QEMU仿真(模糊测试或调试时有用)
    * 检测实施缺陷(CWE漏洞)
    * 固件对比(识别新版本固件发生的改动)
    * 找到其他有相同漏洞的固件
        * 可在过往分析结果中进行模式匹配搜索
* 插件
    * inary analysis 
    * ip and uri finder
    * binwalk
    * known vulnerabilities
    * cpu architecture
    * malware scanner
    * crypto hints
    * manufacturer detection
    * crypto material
    * printable strings
    * cve lookup
    * qemu exec
    * cwe checker 
    * software components
    * elf analysis 
    * software version string finder
    * exploit mitigations
    * file system metadata
    * source code analysis
