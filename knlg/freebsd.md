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
    * `/etc/rc.d/netif restart`
* 系统
    * 手动同步时间: `ntpdate -b pool.ntp.org`
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