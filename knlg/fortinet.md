* 固件下载: https://fortiweb.ru/en/download/

# 逆向
## 提取固件
* 工具
    * `libguestfs-tools`: 有`virt-filesystems`, `guestmount`等工具. 
        * 安装: `sudo apt install libguestfs-tools`
* 查看磁盘分区: `sudo virt-filesystems -a fortios.vmdk`
* 挂载磁盘分区: `sudo guestmount -a fortios.vmdk -m /dev/sda1 ./fortios`


# 漏洞分析
# CVE-2024-21762
* 参考: 
    * [FortiGate SSLVPN CVE-2024-21762漏洞利用分析](https://research.qianxin.com/archives/1854)