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

* 固件解包
    * squashfs
        ```sh
            # 安装
            apt install -y squashfs-tools

            # 解压
            unsquashfs squashfs.img

            # 也可以直接挂载: mount squashfs.img my_dir/

            # 重新打包
            mksquashfs squashfs-root/ squashfs.img -comp xz -Xbcj x86 -e boot
        ```
* U-boot
    * 参考
        * [U-Boot源码解析](https://people.umass.edu/tongping/book/ubootframework.pdf)
        
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

        # 另一种手动运行的方法
        ./scratch/<IID>/run.sh
        python ./debug.py <IID> # 另开shell窗口
    ```
    * 例: `./run.sh -d dlink ../DIR-615_REVE_FIRMWARE_5.00.ZIP 4`
    * 清理缓存: `./scripts/delete.sh <IID>`
    * 挂载: `./scripts/mount.sh <IID>`, 然后cd到`./scratch/<IID>/image`
    * 卸载: `./scripts/umount.sh <IID>`
    * telnet连接: `telnet 192.168.0.1 31338`
    * 直接使用已有iid运行仿真: `./scripts/run.sh <IID> <ARCH>`
* 运行流程(`run.sh`)
    * 用`extractor.py`从固件中提取出根文件系统和内核镜像. 通过判断`./images/$IID.tar.gz`是否存在, 确认是否解压成功.
    * 用`getArch.py`获取架构和字节序. 
    * 用`inferKernel.py`从内核镜像中获取`Linux Version ...`信息和`init=`信息(如, `init=/sbin/preinit`). 
    * 用`makeImage.sh`制作qemu镜像. 
    * 执行`makeNetwork.py`: 运行仿真, 获得串口日志, 根据日志中的信息推测网络配置; 再运行一次仿真(`test_emulation.sh`), 判断是否可ping通以及web是否可用(`check_network`). 结果记录到`makeNetwork.log`. 
    * 根据选择的操作模式(`analyze`, `debug`, `run`, `boot`)进行下一步操作: 
        * `analyze`: 
            * `run_analyze.sh`
            * `analyses_all.sh`
        * `debug`: 
            * `./scratch/$IID/run_debug.sh &`: 在后台运行仿真. 
            * `check_network ${IP} true`: IP是从`${WORK_DIR}/ip`文件读取来. 这一步使用curl和ping检查web服务及网络的可用性. 
            * `./debug.py ${IID}`: 运行交互程序, 可用于通过shell访问仿真. 
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
    * `scratch/`: 仿真时使用的目录, 每个固件对应一个`<IID>`目录. 
        * `<IID>/`
            * `image/`: 用于挂载`image.raw`镜像
            * `init`: 在`makeImage.sh`运行时由`image/firmadyne/init`移过来, 其中的内容由`inferFile.sh`写入. 
            * ``: 
    * `scripts/`: 
        * `delete.sh`: 用法`./scripts/delete.sh <IID>`, 删除某个固件及其数据. 
        * `fixImage.sh`
        * `preInit.sh`: 作为Linux内核命令行中initrd启动用的脚本(`rdinit=/firmadyne/preInit.sh`)
        * `getArch.sh`: 获取cpu架构, 写入数据库. 
            * 用法: `getArch.sh ./images/<解压得到的tar包>`
            * 基本原理: 获取文件系统中的二进制可执行文件, 比如`/bin`和`/sbin`目录下的文件, 执行`file`命令. 
            * 在`run.sh`中调用, 并讲结果写入数据库和`scratch/<IID>/architecture`文件. 
        * `inferDefault.py`:
            * 从`qemu.initial.serial.log`中解析出现的nvram键值对, 记录到`nvram_keys`文件中
            * 搜索整个根文件系统, 记录所有与nvram相关的文件(判断依据: nvram键名有一半出现在文件中). 
            * 该文件在`makeNetwork.py`中被调用
        * `inferKernel.py`: 被`run.sh`调用, 用`strings`从提取的kernel文件中读取字符串: 
            * 读取linux内核版本信息, 记录到`scratch/<IID>/kernelVersion`
            * 找到包含`init=/`的字符串(识别为linux内核命令行), 记录到`scratch/<IID>/kernelCmd`
            * 将`kernelCmd`记录的内核命令行按空格分隔, 找到`init=/xxx`项, 记录到`scratch/<IID>/kernelInit`
        * `inferFile.sh`: 由`makeImage.sh`调用, 且是通过chroot调用(切换到`scratch/<IID>/image`目录)
            * 从`kernelInit`文件提取每一行的`=`右侧的服务路径, 记到`arr`中
            * 若有`/init`, 加入`$arr`中
            * 寻找`preinitMT`, `preinit`, `rcS`文件, 加入`$arr`中
            * 读取`$arr`的每一项: 从`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`中找到同名文件, 然后创建符号链接指向该文件. 将软链接文件路径写入`/firmadyne/init`. 
            * `echo /firmadyne/preInit.sh >> /firmadyne/init`
            * 将以下各项写入到`/firmadyne/service`(前提是这些文件存在)
                * `/etc/init.d/uhttpd start`
                * `/usr/bin/httpd`
                * `/usr/sbin/httpd`
                * `/bin/goahead`
                * `/bin/alphapd`
                * `/bin/boa`
                * `/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf`
            * 将以下各项写入到`/firmadyne/service_name`
                * `uhttpd`
                * `httpd`
                * `goahead`
                * `alphapd`
                * `boa`
                * `lighttpd`
        * `network.sh`: 配置网卡(IP地址等)
        * `makeNetwork.py`
            * 运行仿真, 获得系统运行日志`qemu.initial.serial.log`
            * 根据运行日志, 搜集信息: 
                * 协议, 地址, 端口
                * 找到所有非lo网卡及其IP地址(内核中钩了`__inet_insert_ifa`并打印了网卡信息)
                * 总结得到信息: (ip, dev, vlan_id, mac, br)
        * `test_emulation.sh`: 运行仿真, 检查网络是否可ping通以及web服务是否可用, 结果写入到`ping`, `ip`, `web`, `time_ping`和`time_web`. 在`makeNetwork.py`中被调用. 
        * `makeImage.sh`: 在`scripts`目录下, 制作镜像. 
            * 
                ```sh
                    # 新建`scratch/<IID>`目录
                    # IMAGE即为`image.raw`
                    # IMAGE_DIR即为`scratch/<IID>/image/`

                    qemu-img create -f raw "${IMAGE}" 1G # 生成qemu镜像

                    # 用`fdisk`对镜像分区:
                        # o, n, p, 1, <回车>, <回车>, w
                    
                    DEVICE=`add_partition ${IMAGE}` # 将img文件和一个loop设备关联. DEVICE表示第一个分区, 形如`/dev/loop1p1`.

                    mkfs.ext2 "${DEVICE}" # 在设备上创建文件系统

                    mount "${DEVICE}" "${IMAGE_DIR}" # 挂载设备到`${IMAGE_DIR}`

                    tar -xf "${WORK_DIR}/$IID.tar.gz" -C "${IMAGE_DIR}" # 将根文件系统压缩包释放到目录中
                    mkdir "${IMAGE_DIR}/firmadyne/"
                    mkdir "${IMAGE_DIR}/firmadyne/libnvram/"
                    mkdir "${IMAGE_DIR}/firmadyne/libnvram.override/"
                    
                    # 将系统的busybox和bash-static拷贝过来, 然后执行以下, 之后删除busybox和bash-static
                    FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /bash-static /inferFile.sh # 执行`inferFile.sh`
                    FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /busybox ash /fixImage.sh # 执行`fixImage.sh`

                    mv ${IMAGE_DIR}/firmadyne/init ${WORK_DIR}
                    cp ${IMAGE_DIR}/firmadyne/service ${WORK_DIR}

                    FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /busybox ash /fixImage.sh

                    mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65
                    cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
                    cp "${SCRIPT_DIR}/network.sh" "${IMAGE_DIR}/firmadyne/network.sh"
                    cp "${SCRIPT_DIR}/run_service.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
                    cp "${SCRIPT_DIR}/injectionChecker.sh" "${IMAGE_DIR}/bin/a"
                    touch "${IMAGE_DIR}/firmadyne/debug.sh"

                    if (! ${FIRMAE_ETC}); then
                        sed -i 's/sleep 60/sleep 15/g' "${IMAGE_DIR}/firmadyne/network.sh"
                        sed -i 's/sleep 120/sleep 30/g' "${IMAGE_DIR}/firmadyne/run_service.sh"
                        sed -i 's@/firmadyne/sh@/bin/sh@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
                        sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
                    fi

                    # 卸载
                    umount "${IMAGE_DIR}"
                    del_partition ${DEVICE:0:$((${#DEVICE}-2))}
                ```

                ```
                    [debug] WORK_DIR: /home/zbh/FirmAFL/firmadyne//scratch//2/
                    [debug] IMAGE: /home/zbh/FirmAFL/firmadyne//scratch//2//image.raw
                    [debug] IMAGE_DIR: /home/zbh/FirmAFL/firmadyne//scratch//2//image/
                    [debug] CONSOLE: /home/zbh/FirmAFL/firmadyne//binaries//console.mipsel
                    [debug] LIBNVRAM: /home/zbh/FirmAFL/firmadyne//binaries//libnvram.so.mipsel
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
            * 要点
                * 不完全支持多文件系统固件. 工具**仅识别第一个看起来像unix文件系统的根文件系统并将其提取**. 
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
            * `extractor.py`
                * `Extractor.extract` -> `ExtractionItem.extract`: 
                    * 调用`tempfile.mkdtemp()`创建临时目录, 并切换工作目录为该目录. 
                    * 调用`binwalk.scan`, 然后对扫描出来的每一项执行: 
                        * `_check_firmware`: 检查是否为已知的固件类型, 若是则用`ExtractionItem.extract`分别提取内核和根文件系统. 
                        * `_check_rootfs`: 检查binwalk描述中是否有`filesystem`, `archive`或`compressed`, 有则进行: 
                            * `Extractor.io_find_rootfs(dir_name)`: 递归检查`dir_name`目录, 找长得像unix文件系统的目录. 最后会返回找到的第一个目录的路径. 
                            * 用`shutil.make_archive`将上一步得到的目录做成tar包. 
                        * `_check_kernel`: 检查是否为内核文件(只支持`Linux`内核). 
                        * `_check_recursive`: 递归调用`ExtractionItem.extract`, 
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
* 内核部分
    * 基本信息
        * 包含了一个内核模块`firmadyne`
        | Parameter | Default   | Values | Description |
        | --------- | --------- | ------ | ----------- |
        | devfs     | 1 (on)    | 0, 1   | Create stubs in devfs and emulate behavior |
        | execute   | 1 (on)    | 0 - 5  | Counter to execute `/firmadyne/console` after 4th `execve()` syscall (requires syscall hooks), 0 to disable |
        | reboot    | 1 (on)    | 0, 1   | Attempt to emulate system reboot by re-executing `/sbin/init` |
        | procfs    | 1 (on)    | 0, 1   | Create stubs in procfs and emulate behavior |
        | syscall   | 255 (all) | 0 - 16 | Output log bitmask for hooking system calls using the `kprobe` framework, 0 to disable |
    * 编译
        ```sh
            mkdir -p build/armel
            cp config.armel build/armel/.config
            make ARCH=arm CROSS_COMPILE=/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi- O=./build/armel zImage -j8

            # 最终生成的内核镜像位置: build/armel/arch/arm/boot/zImage
        ```

        * 自己编译: 
            * 需要找到`device drivers`的最后一项`firmadyne`, 把它勾上. 
* 问题
    * libnvram和strace在交叉编译时出现`''PATH_MAX'' undeclared`    
        * `#include <linux/limits.h>`
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
