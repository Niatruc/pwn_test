* 固件下载: https://fortiweb.ru/en/download/
* 工具
    * https://github.com/rrrrrrri/fgt-gadgets
* 参考
    * [Further Adventures in Fortinet Decryption](https://bishopfox.com/blog/further-adventures-in-fortinet-decryption): 新版本固件提取rootfs
    * [搭建 FortiGate 调试环境 (一)](https://wzt.ac.cn/2023/03/02/fortigate_debug_env1/)
# 使用
* 命令
    * `execute`
        * `ping`
    * `fnsysctl`: 在完成证书认证后可用. 可以使用linux命令, 如`ls`, `ps`, `mv`, `df`等. 
# 逆向
## 提取固件
* 从`.out`文件中提取文件系统: 
    * 固件解密
        * 工具: 
            * https://github.com/optistream/fortigate-crypto
            * https://github.com/BishopFox/forticrack (使用python实现)
                * forticrack原理: https://bishopfox.com/blog/breaking-fortinet-firmware-encryption
* 从`.qcow2`或`.vmdk`文件中提取文件系统: 
    * 工具
        * `libguestfs-tools`: 有`virt-filesystems`, `guestmount`等工具. 
            * 安装: `sudo apt install libguestfs-tools`
    * 查看磁盘分区: `sudo virt-filesystems -a fortios.qcow2`
    * 挂载磁盘分区: `sudo guestmount -a fortios.qcow2 -m /dev/sda1 ./fortios`
        * 默认使用`-w`(写权限)打开, 会挂载失败(`mount: /sysroot: can't read superblock on /dev/sda1`). 要使用`-r`. 
    * 卸载磁盘分区: `sudo guestunmount ./fortios`
    * 提取文件系统: 
        * 对于较老的版本(比如`7.0.0`), 可直接进入后面的步骤; 对于新版本, 需分析flatkc中对rootfs的加解密过程: 
            * 使用ida加载flatkc文件(先用`vmlinux-to-elf`加上符号)
            * 找到`fgt_verify_decrypt`函数, 其中使用`fgt_verifier_key_iv`初始化密钥和初始向量, 之后调用`crypto_chacha20_init(u32 *state, struct chacha20_ctx *ctx, u8 *iv)`, `chacha20_docrypt(u32 *state, u8 *dst, const u8 *src, unsigned int bytes)`进行解密. 
            * `fgt_verifier_key_iv(u_int8 *key, u_int8 *iv)`: 读取`.init.data`节中的常量, 使用sha256算法生成key和iv(各用32字节常量(`28+4`和`27+5`))
        * `gzip -d rootfs.gz`
        * `cpio -i 2> /dev/null < rootfs`: 提取文件系统到当前目录
        * 解压压缩包: 老版本需要用fortinet自带的`xz`和`ftar`, 新版本可直接用公共的`xz`和`tar`
            * 例: 解压`bin`目录的压缩包
                * `sudo chroot . /sbin/xz --check=sha256 -d /bin.tar.xz`
                * `sudo chroot . /sbin/ftar -xf /bin.tar`
    * 打包
        * `bin`等目录压缩成`.tar.xz`文件
            * `sudo chroot . /sbin/ftar -cf /bin.tar bin`
            * `sudo chroot . /sbin/xz --check=sha256 -e /bin.tar`
        * `rootfs`压缩成`rootfs.gz`
            * `find . | cpio -H newc -o > ../rootfs.raw`: 打包当前目录为`rootfs.raw`
            * `cat rootfs.raw | gzip > rootfs.gz`: 把`rootfs.raw`压缩为`rootfs.gz`

## 修改固件文件及重新打包
* 将flatkc打包为bzImage
    * 参考: [vmlinux重新打包zImage/bzImage思路提供](https://www.wunote.cn/article/4170/)
    * 问题记录: 
        * `error: ‘-mindirect-branch’ and ‘-fcf-protection’ are not compatible`
            * 解决: 使用低版本gcc
        * `recipe for target 'drivers/gpu/drm/i915' failed`
            * `make menuconfig`, 找到`Device Drivers` -> `Graphics support` -> `(AGP support)`, 关闭. 

## 仿真
* arm版固件仿真
    * virt-manager: 
        * 在创建虚拟机时勾选`customize configuration before install`
        * 在`overview`中的`Hypervisor Details` -> `Firmware`, 下拉框选择`Custom: /usr/share/AAVMF/AAVMF_CODE.fd`
* 配置网络:

    ```
        config system interface
        edit port1
        set mode static
        set ip 192.168.1.2 255.255.255.0
        set allowaccess http ping https ssh telnet
        end
    ```

    * 注意: 和宿主机的`virbr0`使用同一网段. 
    * 配置完后, 访问`http://192.168.1.2`, 可登录web服务. 之后会要求上传证书. 
* 证书
    * 可查看证书状态: 
        > `get system status`
        > `diagnose debug vm-print-license`

## 文件分析
* `flatkc`
    * 基本信息
        * 压缩镜像文件. 由它来解压`rootfs`. 
        * x64虚拟机中的`flatkc`是bzImage, 需要先转成elf再进行逆向分析: 
            * 用`extract-vmlinux`: `/usr/src/linux-headers-6.5.0-21-generic/scripts/extract-vmlinux flatkc > flatkc.kvm.vmlinux`
            * 用`vmlinux-to-elf`(有符号): `./vmlinux-to-elf flatkc flatkc.kvm.vmlinux`
        * `.out`固件提取出来的`flatkc`:
            * 如果是`BIOS (ia32) ROM Ext`, 可用`vmlinux-to-elf`将之转为elf文件. 

* 内核版本(`fnsysctl cat /proc/version`)

|固件版本|Linux内核版本|
|-|-|
|7.0.0|3.2.16|
|7.4.1|4.19.13|

# 漏洞分析
# CVE-2024-21762
* 参考: 
    * [FortiGate SSLVPN CVE-2024-21762漏洞利用分析](https://research.qianxin.com/archives/1854)

# CVE-2024-47575 (FortiJump)