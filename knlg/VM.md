# virtualbox
* 为防止安装系统时的意外错误, 需在配置中`system`处开启`UEFI`
* 挂载共享文件夹: `sudo mount -t vboxsf public_dir /mnt/shared `
* 启用嵌套VT-x/AMD-V
    * 如果这一项是灰色不可选的，则需执行: `VBoxManage.exe modifyvm win7_x64 --nested-hw-virt on`
# vmware
* 合并vmdk
    * vmware-vdiskmanager.exe -r win7_x64.vmdk -t 0 win7_x64_1.vmdk
        * 第一个引号内为多个原vmdk文件所在路径+磁盘名称(去掉-s001之类).vmdk；
        * 第二个引号内为生产单个文件的路径和名字。

# cuckoo
* Locker文件: 
1. 有的在behavior的generic的每个进程的summary中占不少空间(可接受)，如文件操作，操作大量文件(如生成一堆名为'HOW TO DECRYPT FILE.txt'的文件)
2. 有的会开启大量进程，导致出现大量procmemory-regions节(能占到100万行)；behavior的generic和processes节中项也很多(都能占到10万行)

# docker
## 知识点
* 文件默认在`/var/lib/docker`下
* 镜像可看成不包含系统内核(Linux内核)的操作系统. 
* 镜像是分层结构, 每一次`commit`操作后得到的新镜像都会比原镜像多一层.

```sh
docker run -it --name zbh --privileged=true -v /home/bohan/res/ubuntu_share/pwn_test/:/pwn_test -p 23946:23946 -p 12345:12345 aflpp_installed_pwndbg /sbin/init
```

## 常用命令
### 容器
* 运行容器

    `docker run --name <容器名> -it -v <宿主机目录>:<容器目录> <镜像名>`
 
    `-i`表示交互式操作, `-t`表示终端, `-v`指定挂载目录. 
    
    `-d`可使容器进入后台运行, 之后用`docker exec -it <容器id> /bin/bash`进入.

    `docker start <容器名>`启动一个已经关闭的容器.

* 删除容器: `docker rm -f <容器id>`

* 端口映射

    在run操作中添加参数, `-P`表示将所有容器端口映射到宿主机的随机端口, `-p [<宿主IP>:]<宿主端口>:<容器端口>`则是具体指定的映射. `docker port <容器id>`查看端口映射.

    运行后添加端口映射: `iptables -t nat -A  DOCKER -p tcp --dport <宿主机端口> -j DNAT --to-destination <容器IP>:<容器端口>`

    ```sh
        iptables -t nat -A PREROUTING -m tcp -p tcp --dport 23946 -j DNAT --to-destination 172.17.0.2:80
        iptables -t nat -A POSTROUTING -m tcp -p tcp --dport 80 -d 172.17.0.2 -j SNAT --to-source 192.168.0.104:23946
    ```
* 拷贝文件

    拷贝进容器: `docker cp <宿主机目录> <容器名>:<容器内目录>`. 也可从容器拷贝出到宿主机.

## 镜像
* 将运行中的容器保存为新镜像: `docker commit <容器id> <镜像名>`(镜像名可以是原名, 直接替换原镜像)
* 查看镜像分层: `docker history <镜像名>`
* 删除镜像: `docker rmi <镜像id>`
* 重命名: `docker tag <镜像id> <新名>`
* Dockerfile构建镜像

    首先新建一个目录, 在其中新建文件`Dockerfile`, 写入内容如下(使用`centos`这个镜像为基础, 之后运行`yum`):

    ```
    FROM centos
    RUN yum install vim -y
    ```
    之后运行`docker build -t <镜像名> .`
* `save`, `load`, `import`, `export`
    ```sh
        docker save -o my_image.tar <镜像名>

        docker load -i my_image.tar 

        docker export -o my_image.tar <容器名>

        docker import my_image.tar <容器名>
    ```
    区别: save的镜像再load后能查看分层信息, export的则不能.

### 查看信息
* 打印docker信息: `docker info`
* 打印docker容器信息: `docker inspect <容器id>`
* 查看容器文件系统位置: `docker inspect --format='{{.GraphDriver.Data.MergedDir}}' <容器 ID>`
* 列出镜像: `docker images`
* 列出所有容器: `docker ps -a`

## 常用配置
* 修改docker文件存放位置
    ```sh
    systemctl stop docker.service

    mv /var/lib/docker/ <新路径>

    # 在/lib/systemd/system/docker.service中修改:
    ExecStart=/usr/bin/dockerd --graph <新路径>

    # 重启docker 
    systemctl daemon-reload # 这个后面每次启动docker前可能都要执行一次
    systemctl restart docker.service

    ```
* `/var/docker/containers/<容器id>`目录下的`hostconfig.json`文件, 可改容器的某些配置:
    * `PortBindings`项可配置端口映射, 例如: `"23946/tcp":[{"HostIp":"","HostPort":"23946"}]`

## 错误记录
* 在容器中使用systemctls时报错: `System has not been booted with systemd as init system`

    需要加上`--privileged=true`, 让容器内的root真正拥有root权限, 此外进入容器时运行的程序改为`/sbin/init`: 

        docker run -tid --name <容器名> --privileged=true <镜像> /sbin/init

## 其他
* 更换apt源
    ```sh
    mv /etc/apt/sources.list /etc/apt/sources.list.bak

    cat <<EOF >/etc/apt/sources.list
    deb http://mirrors.ustc.edu.cn/debian stable main contrib non-free
    deb http://mirrors.ustc.edu.cn/debian stable-updates main contrib non-free
    EOF

    apt update

    # 若出现"The following signatures couldn't be verified because the public key is not available", 则:
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys <公钥编码>
    ```

* 移除\<none\>镜像

    `docker rmi $(docker images -f "dangling=true" -q)`