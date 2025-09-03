* 参考
    * [0成本搭建摄像头漏洞挖掘环境](https://www.iotsec-zone.com/article/4)

* 摄像头
    * 已知信息
        * 执行`/bin/busybox sh`: 将会调用`/bin/dsh`, 进一步调用`/sbin/qr`. 终端会出现二维码. 
        * 执行`/bin/busybox bash`则不会有二维码. 