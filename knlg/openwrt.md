# 构建
```sh
    make menuconfig # 

    make -j4 # 其中会去github下载很多项目. 可能会因网络问题出错. 
```

## 生成的文件
* 参考
    * https://itlangzi.com/s/FCZV11.html
* `bin/targets/x86/64`
    * `ext4-combined-efi.img.gz`
        * 使用可读写的ext4分区, 没有squashfs的只读文件系统
        * 根分区可以使用更大的驱动器(e.g. SSD/SATA/mSATA/SATA DOM/NVMe/etc)进行扩展
        * 没有故障安全模式和出厂重置等功能, 这些功能需要squashfs的支持
        * 自带引导分区和根分区以及主引导记录 (MBR) 区域以及更新的 GRUB2
        * 支持efi引导
    * `ext4-combined.img.gz`: 同1, 但不支持efi引导
    * `ext4-rootfs.img.gz`
        * 只有根分区的镜像, 重新安装不会覆盖引导分区和主引导记录 (MBR), 由于不带引导分区, 首次安装需要自行使用grub或者syslinux来引导
        * 使用ext4分区
    * `kernel.bin`: 独立的内核
    * `squashfs-combined-efi.img.gz`
        * squashfs是个只读的文件系统, 相当于windows的ghost, 支持故障安全模式和出厂重置等功能
        * 包含一个只读的根文件系统和一个存储设置以及安装软件可读写的分区
        * 组合模式, 只有不到100MB的空间来存储额外的包和配置, 并且无法扩展根分区
        * 支持efi引导
    * `squashfs-combined.img.gz`: 同5, 但不支持efi引导
    * `squashfs-rootfs.img.gz`
    * `rootfs.tar.gz`
        * 所有的文件都在根目录下
        * 不带引导, 需要自行使用grub或者syslinux来引导