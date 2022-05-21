

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
    * 反反调试插件. SharpOD x64向wow64进程, 注入纯64位code，并且hook ntdll64 api. 

* MapoAnalyzer
    * 让x64dbg拥有和IDA一样的函数识别，反编译功能. 
    * 参考: https://bbs.pediy.com/thread-268502.htm

## 问题
* 在附加时找不到进程
    * 确保`选项` -> `选项` -> `引擎` -> `获取调试特权`已勾选
    * 需要以管理员权限运行x64dbg

# 病毒分析