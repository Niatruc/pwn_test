# JunOS
## CLI
* 参考
    * [Juniper EX4200 命令配置手册](https://cnblogs.com/chenfuhai/p/14683296.html)
* 通过`cli`命令进入cli模式. 
* `configure`: 进入配置模式. `set xxx`之类的都是在这个模式下执行. 这时显示如下: 
    ```
    [edit]
    root# 
    ```
    * `set`
        * `system`
            * `root-authentication plain-text-password`: 设置root的口令. (第一次进入配置模式, 提交前一定要配置这项)
            * `login user <用户名> class <类名> authentication plain-text-password`: 设置root的口令. (第一次进入配置模式, 提交前一定要配置这项)
            * `services`
                * 配置ssh服务
                    ```sh
                        set ssh
                        set netconf ssh
                        set ssh root-login allow # 允许root登录
                    ```
                * `web-managements`: j-web服务
                    ```sh
                        set management-url admin
                        set http port 7777 # 访问端口
                        set http interface ge-1/0/0 # 访问接口
                        set https system-generated-certificate # 由系统自动生成X.509证书
                    ```
        * `login class <类名>`: 创建登录类. 
            * `allow-commands "request system reboot"`: 表示允许执行`"request system reboot"`这三条命令. 
        * `interfaces ge-0/0/0 unit 0 family inet address 192.168.9.103/24`: 配置`ge-0/0/0`端口的IP地址. 
        * (ex交换机)配置vlan, 并将端口加入vlan中
            ```sh
                # 新建vlan接口(ifconfig中显示为vlan.10)
                set vlans "vlan_cmtest" vlan_id 10

                # 对PC连接的接口进行修改: family由inet改为ethernet-switching; 将其加入id为10的vlan
                set interfaces ge-0/0/1  unit 0 family ethernet-switching port-mode access vlan members 10

                set interfaces vlan unit 10 family inet address 192.168.1.1/24 # 给vlan.10接口设置网段
                set vlans vlan l3-interface vlan.10         # vlan子端口和VLAN对应起来
            ```
    * `edit ...`: 进入对某项(如账户, 登陆类)的配置, 参数同`set`. 提示字段会显示当前正在编辑的项(`[edit ...]`). `q`退出. 
    * `commit`: 提交配置
    * `show`: 显示配置, 参数同`set`. 
        * `version`: 系统信息. 
        * `system`
            * `firmware`: 固件信息. 
    * `request`
        * `system`
            * `snapshot`: 在插入U盘的情况下, 这条命令将U盘进行分区, 并备份固件. 
            * `software add no-copy /var/tmp/junos-srxsme-12.3X48-D101-domestic.tgz no-validate reboot`: 使用所给固件压缩包升级系统, 并重启. 
    


## 用户访问和身份验证
* 登陆类(`login class`)
    * `super-class`

## 网络

## veriexec
* 通过验证文件签名, 阻止外部未授权软件的运行. 
* `/bin/sh`不要求验证输入, 因为运行`sh <脚本文件>`也是运行一条交互式命令, 此时系统认为这个动作是受认证用户执行的. 但是如果一个已经验证过的shell脚本中包含启动另一个脚本的指令, 则另一个脚本必须经过签名验证. 
* 每个安装的镜像都包含一个只读的manifest文件. 这个文件中包含所有可执行文件及不变文件(的路径)对应的签名(sha1). 在manifest通过校验的情况下, veriexec加载器会将该menifest文件的内容传给内核. 

# 问题
* `no other family type can be configured on the same interface.`
    > 因为同一个接口不能既是2层又是3层. 在初始配置时, 每个接口默认的family都是`ethernet-switching`. 若要配置成`inet`, 需要先把`ethernet-switching`这条配置删掉. 