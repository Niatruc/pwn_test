* 固件下载: https://fortiweb.ru/en/download/
* 工具
    * https://github.com/rrrrrrri/fgt-gadgets
* 参考
    * [Fortigate Firewalls Hardware - CPU model and number, Memory (RAM) and hard disk size datasheet table](https://yurisk.info/2021/03/14/Fortigate-Firewalls-Hardware-CPU-model-and-number-Memory-size-datasheet-table/)
    * [Further Adventures in Fortinet Decryption](https://bishopfox.com/blog/further-adventures-in-fortinet-decryption): 新版本固件提取rootfs
    * [搭建 FortiGate 调试环境 (一)](https://wzt.ac.cn/2023/03/02/fortigate_debug_env1/)
    * [软件签名增强](https://handbook.fortinet.com.cn/%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86/%E5%9B%BA%E4%BB%B6%E4%B8%8E%E9%85%8D%E7%BD%AE%E7%AE%A1%E7%90%86/%E5%9B%BA%E4%BB%B6%E7%89%88%E6%9C%AC%E7%AE%A1%E7%90%86/software_signature_enhance.html)

# 使用
* 命令
    * `execute`
        * `ping`
    * `fnsysctl`: 在完成证书认证后可用. 可以使用linux命令, 如`ls`, `ps`, `mv`, `df`等. 

## 仿真
* arm版固件仿真
    * virt-manager: 
        * 在创建虚拟机时勾选`customize configuration before install`
        * 在`overview`中的`Hypervisor Details` -> `Firmware`, 下拉框选择`UEFI aarch64: /usr/share/AAVMF/AAVMF_CODE.fd`
    * 使用`qemu-system`:
        ```sh
            # 将qemu的arm efi固件复制到一个镜像文件中(大小须至少64M): 
            truncate -s 64m efi.img
            dd if=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd of=efi.img conv=notrunc

            # 启动系统
            qemu-system-aarch64 -M virt -cpu cortex-a72 -m 4G -hda fortios.qcow2 -drive if=pflash,format=raw,file=efi.img,readonly=on

            # 之后在qemu监视窗口中找`view` -> `serial0`查看串口输出. 
        ```
* x64版固件仿真
    * `qemu-system-x86_64 -m 4G -hda fortios.qcow2 -nic tap,id=net0,ifname=tap_fgt,script=no`
* 配置网络:
    * 创建tap网卡: `tunctl -t tap_fgt`
    * 指定tap网卡的ip并启用网卡: `ifconfig tap_fgt 192.168.1.1 up`
    * qemu启动时指定网卡: `-nic tap,id=net0,ifname=tap_fgt,script=no`
    * fortigate中配置网卡: 

    ```
        config system interface
        edit port1
        set mode static
        set ip 192.168.1.2 255.255.255.0
        set allowaccess http ping https ssh telnet
        end
    ```

    * 注意: 如果使用virt-manager仿真, 则指定IP为和宿主机的`virbr0`相同的网段. 
    * 配置完后, 访问`http://192.168.1.2`, 可登录web服务. 之后会要求上传证书. 
* 证书
    * 可查看证书状态: 
        > `get system status`
        > `diagnose debug vm-print-license`
* 调试
    * 挂载qcow2后, 编辑`extlinux.conf`文件, 在启动行参数(`flatkc`那行)添加`loglevel=8`; 仿真时打开串口输出监视窗, 可以看到更多调试信息. 

# 逆向
## 提取固件
* 实体设备
    * (这里)[https://bishopfox.com/blog/a-look-at-fortijump-cve-2024-47575]提到`flatkc`大概率也被混淆了. 
* 从`.out`文件中提取文件系统: 
    * 固件解密
        * 工具: 
            * https://github.com/optistream/fortigate-crypto
            * https://github.com/BishopFox/forticrack (使用python实现)
                * forticrack原理: https://bishopfox.com/blog/breaking-fortinet-firmware-encryption
        * 解密后: 
            * 可以`binwalk -Mer`提取文件系统. 
            * 也可以挂载: 
                * 先通过`binwalk`找到Linux EXT文件系统的偏移. 
                * `mount -o ro,loop,offset=<偏移> <.out的解密文件> <挂载的目录>`: 挂载到目录. 
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
            * 相关linux函数: 
                * `int mpi_powm(MPI res, MPI base, MPI exp, MPI mod)`: RES = BASE ^ EXP mod MOD
                * `int mpi_read_buffer(MPI a, uint8_t *buf, unsigned buf_len, unsigned *nbytes, int *sign)`: 将一个`mpi`(multi precision integer)读入缓冲区`buf`中. 
                * `MPI mpi_read_raw_data(const void *xbuffer, size_t nbytes)`: 从`xbuffer`中读取字节流为一个整数. `nbytes`是要读取的字节数. 
                * `void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)`: 从`cachep`中分配一个对象. 
            * `7.4.1`
                * 找到`fgt_verify_decrypt`函数, 其中使用`fgt_verifier_key_iv`初始化密钥和初始向量, 之后调用`crypto_chacha20_init(u32 *state, struct chacha20_ctx *ctx, u8 *iv)`, `chacha20_docrypt(u32 *state, u8 *dst, const u8 *src, unsigned int bytes)`进行解密. 
                * `fgt_verifier_key_iv(u_int8 *key, u_int8 *iv)`: 读取`.init.data`节中的常量, 使用sha256算法生成key和iv(各用`32`字节常量(`28+4`和`27+5`))
            * `7.6.1`
                * 同`7.4.1`, 但是用chacha20对`.data`节中一块长为`0x10E`的区域进行解密运算, 得到一个key. 
                * 用`rsa_parse_pub_key(struct rsa_key *rsa_key, const void *key, unsigned int key_len)`从上述`key`中提取rsa公钥, 存到`rsa_key`
                * 用sha256生成了初始16字节密钥和向量
                * 循环, 每回解密16个字节: 
                    * `aes_enc_blk(struct crypto_aes_ctx *ctx, u8 *out, const u8 *in)`
        * `gzip -d rootfs.gz`
        * `cpio -i 2> /dev/null < rootfs`: 提取文件系统到当前目录
        * 解压压缩包: 老版本需要用fortinet自带的`xz`和`ftar`, 新版本可直接用公共的`xz`和`tar`
            * 例: 解压`bin`目录的压缩包
                * `sudo chroot . /sbin/xz --check=sha256 -d /bin.tar.xz`
                * `sudo chroot . /sbin/ftar -xf /bin.tar`

## 修改文件系统后(提权) 
* 植入`busybox`: 
    * 将`busybox`放到根文件系统的`/bin`目录下. 
    * 需要一个跳板程序. 用该程序替代`/bin/smartctl`
        ```c
            #include <unistd.h>

            int main(int argc, char const *argv[])
            {
                if (argc > 1)
                {
                    execvp("/bin/busybox", (char *const *)&argv[1]);
                }
                return 0;
            }
        ```
    * 使用: 
        * `diagnose hardware smartctl sh`: 进入shell命令行. aarch64版中, 之后执行busybox的内置命令(`ls`等)可能需要在前面加上`smartctl`. 
* 植入`gdbserver`: 
    * 放置在`/bin`目录下. 
    * 使用: 
        * 附加`httpsd`进程: `smartctl kill -9 $(smartctl pidof telnetd) && gdbserver 0.0.0.0:23 --attach  $(smartctl pidof httpsd)`
            * `fortigate`固件可能有端口白名单机制, 因此只能用上面的方法绑定开放的23端口. 
* 给`/bin/init`打补丁: 
    * `6.4.13`
        * 直接植入文件后, 启动时会在`Starting system maintenance...`后打印`Done 2728`, 然后关机. 在`init`程序的`main`函数中, 可看到有一些通过`fork`和`waitfor`进行的检查, 失败就会跳到结尾打印`Done 2728`. 
        * 分析: 
            1. 
                * 在`main`函数中: 失败后会有一处打印`"System file integrity init check failed!\n"`
                * 会`fork`并在一个函数中对`/data/.db`和`/data/.db.x`作校验. 可直接在该函数的开头返回(设置`mov eax, 1`以返回1)
            2. 
                * 接着会`fork`并在一个函数中对`.fgtsum`作校验. 可直接在该函数的开头返回(设置`mov eax, 1`以返回1)
    * `7.0.0`
        * 同`6.4.13`, 需要绕过`.fgtsum`校验. 同样可直接在该函数的开头返回1. 
    * `7.4.1`
        * 绕过`do_halt`调用: 
            * 搜索字符串`do_halt`, 引用它的函数即为关机函数`do_halt`. 
            * 在`main`函数有四处判断后引用`do_halt`. 将这四处判断用`nop`或`jmp`绕过. 
        * 绕过`/data/rootfs.gz.chk`检查
            * 搜索字符串`/data/rootfs.gz`
            * 在引用的函数中, 可看到一个rsa签名校验函数被调用了两次, 分别校验`/data/rootfs.gz`和`/data/flatkc`
            * 在上述签名校验函数结尾修改`rax`的值(`xor rax, rax`), 强制让函数返回0. 
        * `init_set_epoll_handler`
            * 搜索字符串`init_set_epoll_handler`, 只有一处引用, 该处下方有一个`getpid`调用. 
            * 打补丁, 在`getpid()`后绕过判断, 强制运行之后的代码. (可将`getpid`函数调用下方的`jnz`指令`nop`掉)
        * 绕过白名单检查
            * 搜索字符串`System file integrity monitor check failed`, 其引用处位于一个if判断内部. 
            * 强制让if判断上方的函数返回1(这个函数校验了`/data/.db`文件). (可将函数调用下方的`jnz`跳转`nop`掉)
* 给`flatkc`打补丁: 
    * 若要绕过rootfs解密, 可在`fgt_verify_initrd`函数开头直接返回, 并将一个未加密的`cpio`打包的`rootfs.gz`传入qcow2镜像. 
    * 若不想绕过解密, 则需要将`fgt_verify_initrd`中调用`fgt_verify_decrypt`函数前的判断绕过, 确保能执行到`fgt_verify_decrypt`. 
    * 绕过白名单检查: 
        * 搜索字符串`severity=alert msg=\"[executable file doesn't have existing hash](%s).`, 引用该字符串的是函数`fos_process_appraise_constprop_0`
        * 补丁: 修改该函数开头处调用`integrity_iint_find`后的跳转逻辑, 让函数直接跳转至末尾(返回0), 绕过对文件hash的比较. 

## 重新打包固件
* (x64版)将`flatkc`打包为`bzImage`
    * 方法一: 使用linux源码编译
        * 参考: [vmlinux重新打包zImage/bzImage思路提供](https://www.wunote.cn/article/4170/)
        * 问题记录: 
            * `error: ‘-mindirect-branch’ and ‘-fcf-protection’ are not compatible`
                * 解决: 使用低版本`gcc`(如ubuntu18的`gcc 7.5`)
            * `recipe for target 'drivers/gpu/drm/i915' failed`
                * `make menuconfig`, 找到`Device Drivers` -> `Graphics support` -> `(AGP support)`, 关闭. 
    * 方法二: 手动修改`flatkc`
        ```sh
            # 分别用`extract-vmlinux`和`vmlinux-to-elf`从flatkc中提取vmlinux(一个无符号, 一个有符号)
            # 然后根据对有符号的vmlinux的逆向分析, 修改无符号的vmlinux
            
            # 用gzip压缩修改后的vmlinux
            cat vmlinux_new | gzip -9 > vmlinux.gz

            # 使用ll查看vmlinux.gz的大小, 如果有变化, 需修改flatkc中解压数据的代码段, 一般就在压缩数据的下方. 
            # 参考后文, 对`input_len`进行修改. 

            # 将原来flatkc文件中的压缩数据部分用0填充
            dd if=/dev/zero of=flatkc bs=1 seek=$((0x41B4)) count=$((0x6e1a51)) conv=notrunc

            # 将新的压缩文件填到flatkc的压缩数据空间中
            dd if=vmlinux.gz of=flatkc bs=1 seek=$((0x41B4)) conv=notrunc
        ```
* `bin`等目录打包成`.tar.xz`文件
    * `sudo chroot . /sbin/ftar -cf /bin.tar bin`
    * `sudo chroot . /sbin/xz --check=sha256 -e /bin.tar`
* `rootfs`打包成`rootfs.gz`
    * 切换到`rootfs`目录, 然后执行`find . | cpio -H newc -o > ../rootfs.raw`, 打包当前目录为`rootfs.raw`
    * `cat rootfs.raw | gzip > rootfs.gz`: 把`rootfs.raw`压缩为`rootfs.gz`
    * 之后需要将`rootfs.gz`加密, 再传入qcow2镜像中. 
* 问题记录
    * `Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(1,0)`
        * 因修改`rootfs.gz`不当引起, 包括未对`rootfs.gz`进行加密处理, 或加密算法有问题. 
    * 将`/bin/smartctl`替换为`busybox`后, 运行`diagnose hardware smartctl ls`出现`applet not found`
        * 因运行上述指令时busybox接收的参数是`{"smartctl", "sh"}`
        * 解决: 另写一个程序替换`/bin/smartctl`, 在程序中通过`execvp("/bin/busybox", &argv[1])`运行`busybox`; 将busybox程序传入bin目录并打包`rootfs.gz`. 

## 提权后使用
* `netstat -ant`: 查看所有tcp连接
* gdbserver
    ```sh
        ps -ef | grep <要调试的进程>

        killall telnetd && gdbserver localhost:23 --attach <进程id> # 使用23端口作为远程调试用的端口
    ```

## 文件分析
* `extlinux.conf`: 引导时用到该配置文件, 其中指出内核文件为`flatkc`, initrd为`rootfs.gz`. 
    * 注: 在arm版本中没有该文件, 可修改`boot/grub/grub.cfg`. 
* `flatkc`
    * `7.4.1` (`x64`)
        * 基本信息
            * 是一个压缩镜像文件(如`bzImage`). 由它来解压`rootfs`. 
            * x64虚拟机中的`flatkc`是`bzImage`, 需要先提取内核elf文件再进行逆向分析: 
                * 用`extract-vmlinux`: `/usr/src/linux-headers-6.5.0-21-generic/scripts/extract-vmlinux flatkc > flatkc.kvm.vmlinux`
                * 用`vmlinux-to-elf`(有符号): `./vmlinux-to-elf flatkc flatkc.kvm.vmlinux`
            * `.out`固件提取出来的`flatkc`:
                * 如果是`BIOS (ia32) ROM Ext`, 可用`vmlinux-to-elf`将其中的内核elf文件提取出来. 
        * 分析
            
            * `0x41B4` ~ `0x6E5C05`: 为压缩的内核镜像文件, 长为`0x6e1a51`
            * `0x6E5C10`: 紧接的代码片段用于解压数据. 
                * 参考Linux内核项目的`arch/x86/boot/compressed/head_64.S`文件: 
                ```x86asm
                        /*
                        * Do the extraction, and jump to the new kernel..
                        */
                        pushq	%rsi			/* Save the real mode argument */
                        movq	%rsi, %rdi		/* real mode address */
                        leaq	boot_heap(%rip), %rsi	/* malloc area for uncompression */
                        leaq	input_data(%rip), %rdx  /* input_data */
                        movl	$z_input_len, %ecx	/* input_len */
                        movq	%rbp, %r8		/* output target address */
                        movq	$z_output_len, %r9	/* decompressed length, end of relocs */
                        call	extract_kernel		/* returns kernel location in %rax */
                        popq	%rsi

                ```
                * 需根据压缩数据的大小, 对`input_len`进行修改. 
    * `7.4.1` (`aarch64`)
        * 基本信息
            * 文件类型: `Linux kernel ARM64 boot executable Image, little-endian, 4K pages`. 大小: 15M. 
            * 不是压缩的内核镜像. 对其使用`vmlinux-to-elf`, 会在文件开头加上elf头部和节头表, 在末尾会加上符号信息和程序头表. 

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

# FortiMail