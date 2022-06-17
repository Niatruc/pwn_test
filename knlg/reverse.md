# 文章
[【干货分享】恶意样本分析手册——常用方法篇](https://bbs.huaweicloud.com/blogs/109534)

# 调试计数
* 调试CreateRemoteThread创建的线程
    * 在主进程创建svchost进程后, 执行CreateRemoteThread前, 打开新的od并附加创建的svchost, 之后来到注入的代码的入口点, 打下断点。然后在主进程那边执行了CreateRemoteThread, 另一个OD中就会断在注入代码入口点处

# 代码混淆
* 混淆技术
    * 基于数据的混淆技术
        * 常量展开
            * 常量折叠是编译器的优化手段之一, 其把源代码中可以算出结果的部分直接计算出, 用结果替代算式. 
            * 常量展开则是把简单的赋值替换成一个能得到这个赋值结果的计算过程. 
        * 数据编码方案
            * 同态加密
        * 插入死代码
        * 恒等运算替换
            * `xor eax, 0FFFFFFFFH`: 相当于not运算符, 对数字的每一位取反
            * `~x + 1`: 相当于`-x`, 即二进制补码
            * `(x << y) | (x >> bits(x) - y)`: 相当于`rcl x, y`, 将x循环左移y位. 循环右移以此类推. 
            * `~-x`: `x - 1`
            * `~-x`: `x - 1`
        * 基于模式的混淆
            * 比如, 把`push reg32`替换为`push imm32`, `mov dword ptr [esp], reg32`, 其结果也是将数值reg32放到栈顶. 
    * 基于控制的混淆技术
        * 标准静态分析的假定: 
            0. 
                * 顺序局部性: 单个基本块编译后的指令是顺序排列的
                * 时间局部性: 编译器的优化工作会把彼此相关的基本块放在一起, 减少分支跳转的数量. 
            1. call只用于函数调用, 且调用目标就是函数起始地址
            2. ret和retn意味着函数的边界
            3. 分支两侧都可能被执行, 分支两侧都是代码而非数据
            4. 很容易确定间接跳转的目标地址
            5. 间接跳转和调用只对应switch和函数指针调用
            6. 所有控制转移的目标地址都是代码, 而非数据
            7. 异常的使用是可以预测的
        * 违反上述假定的混淆
            1. 使用内联函数(把子函数的代码合并到调用代码中), 外联函数(把函数的一部分提取出来构成独立函数)
            2. 破坏顺序局部性/时间局部性
                * 引入无条件分支: 用jmp把顺序代码混淆成意面代码
            3. 基于处理器的控制间接化
                * 用push-ret代替jmp
                * 用call代替jmp
            4. 基于操作系统的控制间接化
                1. 混淆后代码触发一个异常(无效指针, 无效运算，无效指令)
                2. 系统调用异常处理函数
                3. 异常处理函数根据其内部逻辑分发指令流，然后把程序设置到正常状状态
            5. 不透明谓词(opaque predicate): 一个特殊条件结构, 其求值总为true或false
                * 给CFG(控制流图)增加一条新的边. 这条假分支要看着真实. 
                * 可通过计算复杂度很高的算术问题实现. 
    * 同时使用以上两者
        * 插入垃圾代码: 在两块有效代码块间插入死代码. 其中要么有无效指令，要么有跳转到无效地址的跳转指令. 
        * 控制流图展平: 把所有控制结构用一个switch语句(分发器)替代.
            * 可把它看成只针对控制流的部分虚拟化. 
    * 虚拟机
        * 有性能开销, 故通常只对选定的部分进行虚拟化. 
    * 白盒加密

    * 基于栈的混淆
    * 使用不常用指令, 如rcl, sbb, pushf, pushad

# 常见算法
* Lzw算法: https://www.cnblogs.com/mcomco/p/10475329.html


# x64dbg
## 插件
* 插件集合: https://github.com/A-new/x64dbg_plugin

* ret-sync插件
    * 功能: 用于在动态调试时联动ida和od/x64dbg/windbg等调试器
    * 安装方法参考: https://bbs.pediy.com/thread-252634.htm
    * 下载: 
        * https://github.com/bootleg/ret-sync#x64dbg-usage
        * (已编译的项目(od/x64dbg/windbg))[https://dev.azure.com/bootlegdev/ret-sync-release/_build/results?buildId=109&view=artifacts&pathAsName=false&type=publishedArtifacts]
    * 安装(ida和x64dbg)
        * 将Syncplugin.py 和 retsync文件夹拷贝到ida的插件目录
        * 将x64dbg_sync.dp64放到x64dbg的插件目录
    * 启动
        * ida加载目标exe后, `edit` -> `plugins` -> `ret-sync`, 点击restart
        * x64dbg运行exe, 并点击 `插件` -> `SyncPlugin` -> `Enable sync`, 或直接在命令行运行`!sync`

* sharpOd
    * 反反调试插件. SharpOD x64向wow64进程, 注入纯64位code, 并且hook ntdll64 api. 

* MapoAnalyzer
    * 让x64dbg拥有和IDA一样的函数识别, 反编译功能. 
    * 参考: https://bbs.pediy.com/thread-268502.htm

## 问题
* 在附加时找不到进程
    * 确保`选项` -> `选项` -> `引擎` -> `获取调试特权`已勾选
    * 需要以管理员权限运行x64dbg

# 病毒分析