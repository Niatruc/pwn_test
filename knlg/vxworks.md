* 参考
    * [VxWorks操作系统指南](https://www.vxworks.net/component/jdownloads/send/3-vxworks/605-vxworks-operating-system-guide?Itemid=0)
    * [VxWorks 启动流程分析以及溢出测试](https://wh0am1i.com/2024/04/11/vxworks-start-overflow/index.html)
    * Digging Inside the VxWorks OS and Firmware The Holistic Security
    * [VxWorks Software Development Kit (SDK)](https://forums.windriver.com/t/vxworks-software-development-kit-sdk/43)
        * 这里提供了sdk的下载链接(其中的vxworks内核镜像是可引导的). SDK包含: 
            * 交叉编译工具(基于clang/LLVM), 可编译内核模块, 实时程序
            * makefile, cmake
            * 针对指定架构的可引导的vxworks内核镜像
            * 开发应用需要的头文件和库文件
            * wrdbg(wind river调试器)
            * 文档
    * [VxWorks 7 SDK for QEMU (IA)](https://d13321s3lxgewa.cloudfront.net/downloads/wrsdk-vxworks7-docs/2403/README_qemu.html)
        * 这是在上一个链接的页面中提供的参考链接
    * [About the Boot Program](https://ladd00.triumf.ca/~daqweb/doc/vxworks/tornado2/docs/vxworks/netguide/c-booting2.html)

* 基本信息
    * 广泛用于军用和民用航空电子设备(`avionics`)(Boeing 787, 747-8, Airbus A400M), 以及地面航空电子系统(军用/民用雷达)
    * 也用于对安全要求不高(non-safety-critical)但对性能要求高的设备: linksys无线路由器, ...
    * 开发环境: Wind River Workbench(基于Java Eclipse)