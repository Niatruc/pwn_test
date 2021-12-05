# IDA
## 快捷键
f2: 可用于编辑内存数据

## 用pycharm调试ida插件
参考: https://www.cnblogs.com/zknublx/p/7654757.html

1. 使用ida安装路径下的python以及easy_install安装pycharm安装目录下的pydevd-pycharm.egg
```sh
E:\zbh\disasm\IDA7_5\Python38\python.exe E:\zbh\disasm\IDA7_5\Python38\Scripts\easy_install.exe  "E:\PyCharm 2021.1.3\debug-eggs\pydevd-pycharm.egg"
```

2. 在pycharm中新增`Python Debug Server`的配置, 填好服务IP地址和端口, 并F9启动调试服务.

    <img alt="python_debug_server_cfg.jpg" src="./pic/python_debug_server_cfg.jpg" width="70%" height="70%">

3. 在要调试的文件中插入如下代码, **在需要中断的地方的前面都需要插入`pydevd_pycharm.settrace`这行代码,** **可以把这行代码视为断点**.
```py
import pydevd_pycharm
pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)
```

4. 启动IDA, 则将命中断点.

注意:
1. 使用的ida是7.5版本; 使用pycharm企业版才有python debug server
2. 确保没有安装pydevd, 否则会有path mapping没有正确匹配路径的问题.
3. 重新加载并调试插件需要重启IDA(仅仅关掉一个项目并重新打开行不通)

## 一些报错
`Unexpected entries in the plt stub. The file might been modified after linking.`
    
这是在导入文件时报的错. 可执行文件中有.plt.sec节, 且

## IDAPython
注: 
* 从7.4开始使用的是python3.
* [接口变化](https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)

官方文档: [https://hex-rays.com/products/ida/support/idapython_docs/](https://hex-rays.com/products/ida/support/idapython_docs/)



```py

```

## 一些插件
**[ipyida](https://github.com/eset/ipyida)**

快捷键`shift+.`调出窗口, 或`ipython console --existing`在ida外打开.

<img alt="ipyida.jpg" src="./pic/ipyida.jpg" width="50%" height="50%">

# GDB
源码: [http://ftp.gnu.org/gnu/gdb](http://ftp.gnu.org/gnu/gdb)

* 安装过程中可能会更新系统自带的python, 导致与原有gdb使用的python不同, 会造成不少问题. 需要在更新python后, 使用gdb的源码重新编译和构建gdb.
* 安装过程中会自动下载相关pip包, 可以先按[https://www.runoob.com/w3cnote/pip-cn-mirror.html](https://www.runoob.com/w3cnote/pip-cn-mirror.html)设置指定默认的pip源.

## 进入gdb后使用的命令
* 远程调试: `target remote 172.17.0.2:12345`
* 打印内存内容: `x/10dw ptr`, 表示打印`ptr`处40个字节的数据(w为单位, 4个字节), 以十进制的方式(d).
    * x(16进制), d(10), u(10), o(8), t(2), a(地址), i(指令地址), c(字符), s(字符串), f(浮点数)
    * b(1字节), h(2字节), w(4字节), g(8字节)
* 打断点: 
    * `b main.c:377`, 377表示源文件中的行号.
    * 内存断点: watch(写), rwatch(读写, awatch(读写): `watch `

# Cling
一个基于LLVM的C++解释器.

* 下载已编译的工程: [https://root.cern.ch/download/cling/](https://root.cern.ch/download/cling/). 之后将其bin目录添加到PATH环境变量.
* 使用:
  * 直接运行cling.
  * 执行C++代码: `cling '#include <stdio.h>' 'printf("Hello World!\n")'`
  * 用Cling运行C++文件: `cat test.cpp | cling`
* 可在Jupyter Lab中使用, 需先安装kernel:
  ```sh
    cd share/cling/Jupyter/kernel/
    pip3 install -e .
    jupyter-kernelspec install [--user] cling-cpp17
  ```