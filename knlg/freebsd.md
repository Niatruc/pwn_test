* 项目地址: `https://github.com/freebsd/freebsd-src/tree/main`
* 快捷键
    * `ctrl + d`: 补全命令
* 安装桌面
    * 参考
        * [VMware 给 FreeBSD 13 安装 KDE 桌面](https://www.cnblogs.com/Huae/p/16282092.html)
        * [第 4.2 节 安装 KDE 5](https://book.bsdcn.org/di-4-zhang-zhuo-mian-an-zhuang/di-4.2-jie-an-zhuang-kde-5)
    * 相关包
        * kde: 
            * `SDDM (Simple Desktop Display Manager)`: KDE Plasma 5 和 LXQt 桌面环境的首选登录管理器
            * `sddm-kcm`: KConfig Module. 用于设置sddm
        * gnome: 
            * 找不到gnome3, 只能装`gnome-desktop`
            * `gdm`: 
* 构建交叉编译工具链
    * 参考
        * `https://man.freebsd.org/cgi/man.cgi?build(7)`
        * [FreeBSD源码笔记05-内核交叉编译](https://dengwenyi88.github.io/blog/4a62f164.html)
        * [FreeBSD Kernel-编译环境搭建](https://yirannn.com/kernel/37.html)
            * 这篇是在linux下编译freebsd内核(适用于freebsd 13以上版本)
        * [How to make a cross compiler (gcc) for freebsd under linux. A small tutorial.](https://marcelog.github.io/articles/cross_freebsd_compiler_in_linux.html)
            * 在linux上交叉编译运行于freebsd的程序
        * [FreeBSD/arm for Linksys NSLU2 (aka the slug)](https://wiki.freebsd.org/FreeBSDSlug)
        * [build --	General	instructions on	how to build the system](https://man.freebsd.org/cgi/man.cgi?build(7))
    * 步骤
        ```sh
            export BASEDIR=$(pwd)
            export MAKEOBJDIRPREFIX=$BASEDIR/obj
            cd $BASEDIR/freebsd-src-release-8.0.0

            # 构建mips大端版本(如果不指定`TARGET_BIG_ENDIAN`, 默认为小端, 此时gcc编译时指定`-EB`选项就会报错`compiled for a big endian system and target is little endian`)
            make buildworld TARGET_ARCH=mips TARGET_BIG_ENDIAN=true -j4

            # powerpc默认是大端; 没有编译小端的方法. 
        ```

        * 这样生成的工具和适用于目标cpu架构的库文件都放在`obj/mips`下

# 命令
* `find <目录>`
    * `-name "*str*"`: 如果搜索的字符串用到通配符, 须给字符串加上双引号. 
* 软件管理
    * `pkg`
        * `install <包>`
        * `update -f`
        * 配置: 
            * `/etc/pkg/FreeBSD.conf`这个配置文件会随着`freebsd-update`跟新. 
            * `/usr/local/etc/pkg/repos/FreeBSD.conf`
        * 离线安装包: 
            * 获取: `http://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/i386/8.0-RELEASE/packages/lang/`
            * 然后: `pkg_add xxx.tbz`
* 服务
    * `service`
        * `-e`: 列出已启动的服务
* 用户
    * `logins`: 列出所有用户
    * 列出所有组: 
        * `cat /etc/groups`
        * `getent group`
    * `adduser`
        * `adduser -g video -s sh -w yes`: 创建一个普通用户(用户名为 ykla), 并将其添加到 video 分组
    * `pw`: 用于用户和组的创建和修改等操作. 
        * `usermod <用户> -G <组>`: 将用户添加到组. 
* 文件
    * `locate <文件名>`: 用于搜索文件
    * `/usr/libexec/locate.updatedb`: 更新locate数据库. 
* 网络
    * `netstat`
        * `-an`: 显示所有网络连接
        * `-rn`: 打印路由表
    * `/etc/rc.d/netif restart`: 重启网络
    * `/etc/netstart`: 修改`/etc/rc.conf`
    * `/etc/rc.conf`: 
        ```conf
            ifconfig_em0="inet 192.168.1.100 netmask 255.255.255.0" # 设置网卡IP. 值为`DHCP`则自动获取IP. 
            defaultrouter="192.168.1.1" # 设置网关
        ```
* 系统
    * 手动同步时间: `ntpdate -b pool.ntp.org`
        * 参考: `https://blog.neilpang.com/freebsd-%E4%BD%BF%E7%94%A8-ntpdate-%E5%92%8C-ntpd-%E8%87%AA%E5%8A%A8%E6%9B%B4%E6%96%B0%E7%B3%BB%E7%BB%9F%E6%97%B6%E9%97%B4/`
    * `sysctl`
        * `hw.byteorder`: 
        * `hw.machine`: 
        * `hw.byteorder`: 

# 编程
* 获取错误信息
    ```cpp
    // 没有perror函数, 只能用如下方法: 
    printf("%s\n", strerror(errno));
    ```
* `kqueue`
    * 参考
        * [Kqueue: A generic and scalable event notification facility](https://people.freebsd.org/~jlemon/papers/kqueue.pdf)
        * [kqueue tutorial](https://wiki.netbsd.org/tutorials/kqueue_tutorial/)
        * [[13]APUE：KQUEUE / FreeBSD](https://www.cnblogs.com/hadex/p/6201279.html)
        * [Handling TCP Connections with Kqueue Event Notification](https://eradman.com/posts/kqueue-tcp.html)

# 问题
* `pkg update`或`pkg install`时出现`No SRV record found for the xxx`
    * 把`/usr/local/etc/pkg/repos/FreeBSD.conf`中url的`pkg+`去掉. 
* 键盘鼠标不能用
    * `/etc/rc.conf`
        > moused_enable="YES"
* `/usr/local/lib/libtasn1.so.6: Undefined symbol "strverscmp@FBSD_1.7"`
    * 将系统从`13.1`更新到`13.2`. 参考`https://www.freebsd.org/releases/13.2R/installation/`
* gcc编译问题
    * `netinet/ip.h error: expected specifier-qualifier-list before 'u_int'`, `netinet/ip.h error: field 'ip_src' has incomplete type`
        * 需先包含头文件`<sys/types.h>`和`<netinet/in.h>`