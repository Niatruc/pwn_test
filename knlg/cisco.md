# 思科路由器固件
* 路由器用的两种镜像
    * 系统镜像(system image)
        * 路由器boot的时候加载的镜像. 
        * 存放于闪存. 
    * 引导镜像(boot image)
        * 负责网络引导, 加载ios镜像到路由器. 
        * 根据平台的不同, 又称为: xboot镜像, rxboot镜像, bootstrap镜像, boot loader/helper镜像. 
        * 有些平台将其保存在ROM中, 有些则保存在闪存中. 
* SP(supervisor engine): 
* RP(route processor): 
* RSP(route switch processor): 
* `sup-bootflash`, `sup-bootdisk`: 位于引擎主板上. SP的flash, 一般200M以上, 适合存放ios. 
* `bootflash`: 位于MSFC板卡上. RP的flash, 一般64M左右, 可更换. 

# Rommon(ROM Monitor)
* 又称boot软件, boot镜像. 路由器通电后, rommon对路由器做初始化, 然后将控制权转给ios. 之后rommon就不再被使用. 
* 与ios之间的联系: 
    * rommon环境变量: 指明了ios软件的位置, 并描述了如何加载ios. 
    * 配置寄存器: 控制了一个板卡的启动. 
        * 指定路由器以管理员EXEC模式还是rommon模式开启. 
* 升级
    * `show platform`或`show rom-monitor`, 查看当前使用的rommon. 
    * 若rommon镜像不在路由中, 将镜像拷贝到其bootflash或usb[0-1]上. (使用`copy`命令)
    * 使用`dir`命令检查rommon文件是否已拷贝进来. 
    * `upgrade rom-monitor filename <location> all`
    * `reload`
    * 若没有自动boot, 则手动使用`boot`命令. 直到ios镜像被引导完成之前, rommon的更新都还不是持久的. 
    * 使用`enable`命令, 在引导完成后进入EXEC模式. 
    * 再次`show platform`, 确认已更新. 

# 思科操作系统
* IOS
    * 特性
        * 庞大单一(monolithic), 不支持外部模块(插件). 更新固件时需要全部更新. 
        * 压缩文件, 用的是改过的pkzip格式. 
        * 内存
            * 内存分为进程内存和IO内存. 内存分为堆块, 由双向链表管理. 
            * 栈也是用堆块组成的. IOS分配给进程的栈很小(6000字节). 栈溢出可能覆写堆块头部. 
            * `checkheaps`会周期性检查堆完整性. 
        * 一点异常都可以引发重启. 
        * watchdog会检查进程是否超时. 
        * 优先级: 0~15, 15是最高等级. 
* IOS XE
    * 特性
        * 基于Linux内核, 模块化. 可更新单独一个组件. 
        * IOS作为一个daemon运行于Linux内核上. 
# 思科路由器终端操作
* 模式
    * 用户模式
    * 特权模式
        * `enable`: 进入特权模式
        * `disable`: 返回用户模式
        * `copy tftp: flash: `: 进入交互程序, 从tftp服务器下载文件到flash
        * `dir flash: `: 
    * 全局模式
        * `configure terminal`: 进入全局模式, 以修改运行配置
        * `hostname <主机名>`
        * `enable password <密码>`: 设置进入特权模式用的密码(`running-config`文件中显示明文密码)
            * `no enable password`: 禁用口令
        * `enable secret <密码>`: 设置进入特权模式用的密码(`running-config`文件中显示处理后的密码)(这个口令优先于上面的)
        * `write`: 写配置
        * `copy running-config startup-config`: 用更新的配置文件覆盖启动配置文件
        * `show startup-config`: 显示配置
        * `upgrade rom-monitor`
            * `SREC`(Motorola S-record): 用ASCII文字表示十六进制的文本文档
                * 每一行格式: |S|记录种类|字节数量|地址|数据|检查码|
                    * 每一行开头为`S`
                    * 记录种类: 0-9
                        * 1: 地址是两个字节
                        * 2: 地址是三个字节
                        * 3: 地址是四个字节
                    * 字节数量: 记录剩余的字节数. 至少是3. 
                * 例: `S1137AF00A0A0D0000000000000000000000000061`
                    * 拆分: |S1|13|7AF0|0A0A0D00000000000000000000000000|61|
                    * S1
                    * 13个字节
                    * 地址是7AF0
                    * 检查码的计算方法: 
                        * 加总: 将每个字节相加 13 + 7A+F0 + 0A+0A+0D+00+00+00+00+00+00+00+00+00+00+00+00+00 = 19E 
                        * 取最低字节: 总和的最低字节 = 9E.
                        * 取补数: 计算最低字节的一补数, FF - 9E = 61. 
                * 解析和转换工具: 
                    * `srec_info`
        * `tftp-server <文件>`: 配置tftp服务. 可从其他地方使用tftp客户端下载指定文件. 
            * 如, 在Windows中, 启用tftp客户端后, 在终端中执行`tftp -i <路由器IP> get <目标文件>`, 即可下载文件. 
    * 子模式
        * 接口模式(interface mode)
            * `interface fa0/0`: 进入接口模式(fastEternet接口0/0)
            * `ip address <IP地址> <掩码>`: 配置接口IP地址
            * `no shut`: 用以在配置完后打开接口
        * 线路模式(line mode)
            * `aux 0`: 设置辅助口令
            * `console 0`: 设置控制台口令
            * `vty 0 4`: 配置telnet口令(`0 4`: 允许5个终端同时远程登录)
            * 执行上面的命令后, 都可以通过`password`设置对应口令
            * `privilege level 15`: 配置登录权限为15级(默认为1)
            * `transport input ssh telnet`: 配置远程登录方式为ssh和telnet
        * 路由模式(router mode)
            * `router rip`: 进入路由模式(rip协议)
    * Setup模式
    * Rommon模式
        * 进入: 
            * 进入全局模式
            * `config-register 0x0`: 重置配置寄存器
            * `exit`
            * `reload`: 以新的配置寄存器的值重新引导路由. 路由器会停留在rom monitor, 且不会引导ios(需要手动boot). 
        * `boot system sup-bootflash:<ios文件名>`: 引导ios
        * `confreg`: 修改的配置寄存器. 
            * `confreg 0x2100`: 开启调试功能. 
        * `set`: 显示环境变量. 
        * `unset`: 取消一个环境变量的设置. 
        * `dir`: 显示文件. 
        * `dev`: 显示可使用的本地存储设备. 
        * `showrom`: 显示当前选择的rommon. 
        * `sync`: 保存配置(将rommon变量写入到NVRAM介质). 
        * 环境变量: 
            * `IP_ADDRESS`: 
            * `IP_SUBNET_MASK`: 
            * `DEFAULT_GATEWAY`: 
            * `TFTP_SERVER=path/file`: 设置引导软件镜像的目录即文件名
            * `BOOT=path/file`: 为某个节点指定引导的软件. 
            * `PS1`: 指定终端会话的前缀(默认是`rommon ! >`). 如果在rommon模式下操纵多个路由器, 则这个设置会有用. 

* 其它命令
    * `logout`: 退出控制台
    
    * `show`
        * `boot`: 查看系统通过什么位置的什么文件启动. 
        * `running-config`: 打印配置文件
        * `version`: 
        * `processes`: 
        * `memory`: 
        * `buffers`: 
            * `all`: 
        * `ip`: 
            * `interface`: 显示网卡信息
                * `brief`: 
        * `file`: 
            * `systems`: 列出文件系统
        * `romvar`: 显示rommon变量
        * `platform`: 硬件信息
        * `rom-monitor`: 显示rommon的版本号
        * ``: 
    
    * `dir <文件位置>`: 枚举文件

    * 配置
        * `line`
    * 快捷键
        * `ctrl + A`: 移动光标到本行的开始处
        * `ctrl + E`: 移动光标到本行的结尾处
        * `ESC + B`: 向前移动一个单词
        * `ESC + F`: 向后移动一个单词
        * `ctrl + B`: 向前移动一个字符
        * `ctrl + F`: 向后移动一个字符
        * `ctrl + W`: 向前删除一个单词
        * `alt + D`: 向后删除一个单词
        * `ctrl + Z`: 结束配置模式, 返沪执行模式

    * `tclsh`