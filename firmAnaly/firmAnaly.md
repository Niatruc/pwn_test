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

# Firmadyne
* 参考
    * [\[原创\]firmadyne源码解析-揭开固件模拟的黑盒面纱](https://bbs.kanxue.com/thread-286135.htm)

# FirmAE
* 参考: [FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis阅读笔记](https://zhuanlan.zhihu.com/p/540725241)
* 使用
    ```sh
        ./download.sh # 下载文件到`binaries/` (linux内核文件, busybox, console, libnvram, gdb, gdbserver, strace)
        
        # 导入数据库
        # 安装必要软件(docker, binwalk, qemu等)
        ./install.sh
        
        ./init.sh # 启动postgresql服务
        
        # 检查仿真. 
        # 会在`images/`目录下生成`<IID>.kernel`和`<IID>.tar.xz`, 在`scratch/<IID>`目录下生成`image.raw`以及多个记录固件信息的文本文件
        sudo ./run.sh -c <brand> <firmware> 

        sudo ./run.sh -a <brand> <firmware> # 分析模式(调用`analyses/analyses_all.sh`扫描漏洞)
        sudo ./run.sh -r <brand> <firmware> # 运行模式
        sudo ./run.sh -d <brand> <firmware> # 调试模式(调用`debug.py`, 仿真成功后将出现一个菜单, 可调用socat, shell, tcpdump, gdbserver, 文件传输等功能)
    ```
    * 例: `./run.sh -d dlink ../DIR-615_REVE_FIRMWARE_5.00.ZIP 4`
    * 清理缓存: `./scripts/delete.sh 4`
    * 挂载: `./scripts/mount.sh <IID>`, 然后cd到`./scratch/<IID>/image`
    * 卸载: `./scripts/umount.sh <IID>`
    * telnet连接: `telnet 192.168.0.1 31338`
* 运行流程(`run.sh`)
    * 用`extractor.py`从固件中提取出根文件系统和内核镜像. 通过判断`./images/$IID.tar.gz`是否存在, 确认是否解压成功.
    * 用`getArch.py`获取架构和字节序. 
    * 用`inferKernel.py`从内核镜像中获取`Linux Version ...`信息和`init=`信息(如, `init=/sbin/preinit`). 
    * 用`makeImage.sh`制作qemu镜像. 
    * 用`makeNetwork.py`, 运行仿真, 获得串口日志, 根据日志中的信息推测网络配置. 结果记录到`makeNetwork.log`
* 项目文件:
    * `binaries/`: 
        * `console.<arch>`: 
            * 该程序将stdin和stdout重定向到`/firmadyne/ttyS1`(即com2串口, 该设备在`makeImage.sh`中通过`mknod`生成), 然后用`execl`执行`/bin/sh`
            * 内核中执行`execve`时, 会运行console程序. (`drivers/firmadyne/hooks.c:execve_hook`)
        * `libnvram.so.<arch>`: 这个库模拟NVRAM外围设备, 方法是将键值对存储在`tmpfs`(默认挂载在`/firmadyne/libnvram`目录)
        * `vmlinux.<arch>`, `zImage.<arch>`: 内核文件
    * `database/`: 
    * `Dockerfile`: 
    * `download.sh`: 下载`binaries/`目录下的文件
    * `example_analysis.sh`: 
    * `firmadyne.config`: `scripts/`下的脚本用到. 定义了一些`get_xxx`, `check_xxx`函数. 
    * `images/`: 存放制作的qemu镜像
    * `LICENSE.txt`: 
    * `paper/`: 
    * `README.md`: 
    * `scratch/`: 仿真时使用的目录, 每个固件对应一个`<id>`目录. 
    * `scripts/`: 
        * `delete.sh`: 用法`./scripts/delete.sh <id>`, 删除某个固件及其数据. 
        * `fixImage.sh`
        * `preInit.sh`: 作为Linux内核命令行中initrd启动用的脚本(`rdinit=/firmadyne/preInit.sh`)
        * `getArch.sh`: 获取cpu架构, 写入数据库. 
            * 用法: `getArch.sh ./images/<解压得到的tar包>`
            * 基本原理: 获取文件系统中的二进制可执行文件, 比如`/bin`和`/sbin`目录下的文件, 执行`file`命令. 
            * 在`run.sh`中调用, 并讲结果写入数据库和`scratch/<ID>/architecture`文件. 
        * `inferDefault.py`:
            * 从`qemu.initial.serial.log`中解析出现的nvram键值对, 记录到`nvram_keys`文件中
            * 搜索整个根文件系统, 记录所有与nvram相关的文件(判断依据: nvram键名有一半出现在文件中). 
            * 该文件在`makeNetwork.py`中被调用
        * `inferFile.sh`: 
        * `network.sh`: 配置网卡(IP地址等)
        * `makeNetwork.py`
            * 运行仿真, 获得系统运行日志`qemu.initial.serial.log`
            * 根据运行日志, 搜集信息: 
                * 协议, 地址, 端口
                * 找到所有非lo网卡及其IP地址(内核中钩了`__inet_insert_ifa`并打印了网卡信息)
                * 总结得到信息: (ip, dev, vlan_id, mac, br)
        * `test_emulation.sh`: 运行仿真, 检查网络是否可ping通以及web服务是否可用, 结果写入到`time_ping`和`time_web`. 在`makeNetwork.py`中被调用. 
        * `makeImage.sh`: 在`scratch/<ID>`目录下, 制作镜像
            * 
                ```sh
                    # 新建`scratch/<ID>`目录

                    qemu-img create -f raw "scratch/<ID>image.raw" # 生成qemu镜像

                    # 用`fdisk`对镜像分区:
                        # o, n, p, 1, <回车>, <回车>, w
                    
                    kpartx -a -s -v "${IMAGE}" # kpartx挂载qemu镜像文件, 之后可在`/dev/mapper`下看到设备loop9p1

                    mkfs.ext2 "${DEVICE}" # 在设备上创建文件系统

                    mount "${DEVICE}" "${IMAGE_DIR}" # 挂载设备到`${IMAGE_DIR}`
                    
                    # 拷贝
                    cp "${CONSOLE}" "${IMAGE_DIR}/firmadyne/console"
                    cp "${LIBNVRAM}" "${IMAGE_DIR}/firmadyne/libnvram.so"
                    mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65
                    cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
                    cp -r "${IMAGE_DIR}" "${FIRMWARE_DIR}/../image_${IID}" # 将目录拷贝到`image_${IID}`

                    # 卸载
                    umount "${DEVICE}"
                    kpartx -d "${IMAGE}" # 卸载
                    losetup -d "${DEVICE}" &>/dev/null
                    dmsetup remove $(basename "$DEVICE") &>/dev/null
                ```

                ```
                    [debug] WORK_DIR: /home/cmtest/FirmAFL/firmadyne//scratch//2/
                    [debug] IMAGE: /home/cmtest/FirmAFL/firmadyne//scratch//2//image.raw
                    [debug] IMAGE_DIR: /home/cmtest/FirmAFL/firmadyne//scratch//2//image/
                    [debug] CONSOLE: /home/cmtest/FirmAFL/firmadyne//binaries//console.mipsel
                    [debug] LIBNVRAM: /home/cmtest/FirmAFL/firmadyne//binaries//libnvram.so.mipsel
                    [debug] DEVICE: /dev/mapper/loop9p1
                ```
        * `mount.sh`
        * `preInit.sh`
        * `run.sh`
        * `run-debug.sh`    
        * `run.<arch>.sh`
        * `run.<arch>-debug.sh`
        * `tar2db.py`
        * `umount.sh`
    * `setup.sh`: 
    * `sources/`: 
        * `console/`: 在系统启动时, 在字符设备`/dev/firmadyne`中启动一个控制台, 以便于与仿真的qemu固件交互(因为有些固件不会在串口控制台启动一个终端, 所以需要这么做). 
        * `extractor/`: 固件提取工具, 用于从基于Linux的固件镜像中提取内核镜像或压缩的文件系统. 
            * 依赖
                * `fakeroot`: 用于模仿sudo操作, 以访问需要root权限的文件或目录. 
                * `psycopg2`: 用于操作postgresql
                * `binwalk`: 
                    * 依赖
                        * `jefferson`
                        * `sasquatch`：包含了许多对`unsquashfs`的补丁, 以支持各供应商自行实现的SquashFS. (SquashFS可以高效地压缩文件系统, 同时保持文件系统结构不变, 支持随机访问和快速加载. SquashFS常被用作Linux发行版的安装介质, 也被用于嵌入式系统的根文件系统)
                * `python-magic`: 用于识别文件类型
            * 用法
                * 会暂时将文件释放到`/tmp`目录. 因为有些文件比较多, 所以最好挂载为`tmpfs`, 即只将文件释放在内存中. (在`extractor.sh`中, 会用docker的`--tmpfs`选项)
                * `fakeroot python3 ./extractor.py -np <infile> <outdir>`
        * `libnvram/`: 用以模拟NVRAM设备的动作. 
            * 
        * `scraper/`
    * `startup.sh`: 
* 注: 
    * 需要先安装`bash-static`, `makeImage.sh`中会把此程序拷贝到固件镜像目录中. 
    * 不能直接进入`scratch/<IID>`目录下执行`run.sh`, 有路径问题. 但可以这样执行: `sudo scratch/<IID>/run.sh`
    * 离线安装
        * binwalk: 手动安装`yaffshiv`, `sasquatch`, `jefferson`, `cramfstools` (`ubi_reader`可以pip直接安装)
            * sasquatch(`https://github.com/devttys0/sasquatch`)
                * 需要对补丁文件`patches/patch0.txt`打补丁(参考`https://github.com/devttys0/sasquatch/issues/48`中`jacopotediosi`的说法, 下载`https://github.com/devttys0/sasquatch/pull/51.patch`)
                
# FACT
* 参考: https://fkie-cad.github.io/FACT_core/index.html
* 安装: 
    * 参考: [FACT installation](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.md)
    * 如果在miniconda环境下安装, 则修改`src/helperFunctions/install.py`中的`is_virtualenv`函数, 直接返回True. 
    * 成功安装的日志: 
        ```sh
            [2025-04-07 01:04:16][install][INFO]: FACT Installer 1.2
            [2025-04-07 01:04:16][common][INFO]: Updating system
            [2025-04-07 01:04:19][install][INFO]: Installing apt-transport-https autoconf automake build-essential git gnupg2 libtool python3 python3-dev unzip wget libfuzzy-dev libmagic-dev
            [2025-04-07 01:04:43][db][INFO]: Skipping PostgreSQL installation. Reason: Already installed.
            [2025-04-07 01:04:46][db][INFO]: Initializing PostgreSQL database
            [2025-04-07 01:04:46][install][INFO]: Installing nodejs papirus-icon-theme
            [2025-04-07 01:05:07][frontend][INFO]: Skipping nodeenv installation (already exists)
            [2025-04-07 01:05:11][frontend][INFO]: Creating directory for authentication
            [2025-04-07 01:05:11][frontend][INFO]: Initializing docker container for radare
            [2025-04-07 01:05:12][frontend][INFO]: Pulling pdf report container
            [2025-04-07 01:05:14][install][INFO]: Installing libjpeg-dev libssl-dev redis binutils file openssl bison flex pkg-config
            [2025-04-07 01:05:24][backend][INFO]: Skipping yara installation: Already installed and up to date
            [2025-04-07 01:05:24][backend][INFO]: Installing checksec.sh
            [2025-04-07 01:05:24][backend][INFO]: Pulling fact extraction container
            [2025-04-07 01:05:26][backend][INFO]: Installing linter plugin.
            [2025-04-07 01:05:50][backend][INFO]: Finished installing linter plugin.

            [2025-04-07 01:05:50][backend][INFO]: Installing cve_lookup plugin.
            [2025-04-07 01:07:49][backend][INFO]: Finished installing cve_lookup plugin.

            [2025-04-07 01:07:49][backend][INFO]: Installing crypto_hints plugin.
            [2025-04-07 01:07:50][backend][INFO]: Finished installing crypto_hints plugin.

            [2025-04-07 01:07:50][backend][INFO]: Installing software_components plugin.
            [2025-04-07 01:07:52][backend][INFO]: Finished installing software_components plugin.

            [2025-04-07 01:07:52][backend][INFO]: Installing binwalk plugin.
            [2025-04-07 01:08:02][backend][INFO]: Finished installing binwalk plugin.

            [2025-04-07 01:08:02][backend][INFO]: Installing qemu_exec plugin.
            [2025-04-07 01:08:06][backend][INFO]: Finished installing qemu_exec plugin.

            [2025-04-07 01:08:06][backend][INFO]: Installing known_vulnerabilities plugin.
            [2025-04-07 01:08:07][backend][INFO]: Finished installing known_vulnerabilities plugin.

            [2025-04-07 01:08:07][backend][INFO]: Installing device_tree plugin.
            [2025-04-07 01:08:07][backend][INFO]: Finished installing device_tree plugin.

            [2025-04-07 01:08:07][backend][INFO]: Installing ipc plugin.
            [2025-04-07 01:08:08][backend][INFO]: Finished installing ipc plugin.

            [2025-04-07 01:08:08][backend][INFO]: Installing file_system_metadata plugin.
            [2025-04-07 01:08:08][backend][INFO]: Finished installing file_system_metadata plugin.

            [2025-04-07 01:08:08][backend][INFO]: Installing ip_and_uri_finder plugin.
            [2025-04-07 01:08:16][backend][INFO]: Finished installing ip_and_uri_finder plugin.

            [2025-04-07 01:08:16][backend][INFO]: Installing kernel_config plugin.
            [2025-04-07 01:08:21][backend][INFO]: Finished installing kernel_config plugin.

            [2025-04-07 01:08:21][backend][INFO]: Installing architecture_detection plugin.
            [2025-04-07 01:08:23][backend][INFO]: Finished installing architecture_detection plugin.

            [2025-04-07 01:08:23][backend][INFO]: Installing cwe_checker plugin.
            [2025-04-07 01:08:25][backend][INFO]: Finished installing cwe_checker plugin.

            [2025-04-07 01:08:25][backend][INFO]: Installing input_vectors plugin.
            [2025-04-07 01:08:26][backend][INFO]: Finished installing input_vectors plugin.

            [2025-04-07 01:08:26][backend][INFO]: Installing users_and_passwords plugin.
            [2025-04-07 01:08:29][backend][INFO]: Finished installing users_and_passwords plugin.

            [2025-04-07 01:08:29][backend][INFO]: Creating firmware directory
            Create signature directory /home/zbh/Desktop/FACT_core/src/analysis/signatures
            Compile signatures in /home/zbh/Desktop/FACT_core/src/plugins/analysis/crypto_material/signatures
            Compile signatures in /home/zbh/Desktop/FACT_core/src/plugins/analysis/crypto_hints/signatures
            Compile signatures in /home/zbh/Desktop/FACT_core/src/plugins/analysis/software_components/signatures
            Compile signatures in /home/zbh/Desktop/FACT_core/src/plugins/analysis/known_vulnerabilities/signatures
            [2025-04-07 01:08:29][install][INFO]: installation complete
        ```
    * 问题: 
        * 安装uwsgi时出错提示`undefined reference to 'SSL_get_peer_certificate'`, 疑似与ssl版本, 且在conda环境下才会有此问题. 
            * 参考: https://github.com/unbit/uwsgi/issues/1516
                ```sh
                    # 方法1: 
                    conda config --add channels conda-forge
                    conda install uwsgi

                    # 方法2: 
                    pip install pyuwsgi
                ```
        * `uwsgi: error while loading shared libraries: libcrypt.so.2: cannot open shared object file: No such file or directory`
            * 解决: 用`pip install pyuwsgi`安装uwsgi
        * `docker build -t fact/john:alpine-3.18 FACT_core/src/plugins/analysis/users_and_passwords/docker`时出现网络超时问题. 
            * 分析: `FACT_core/src/plugins/analysis/users_and_passwords/docker/Dockerfile`文件中有`RUN curl -s https://raw.githubusercontent.com/danielmiessler/...`命令, 该网址大概被墙了. 
            * 解决: 修改Dockerfile, 添加`ENV http_proxy=<代理地址>`, `ENV https_proxy=<代理地址>`, `ENV ftp_proxy=<代理地址>`
* 启动服务
    * 运行`src/start_fact.py`
    * 访问`http://localhost:5000`
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
