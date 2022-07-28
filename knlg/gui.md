# QT
## 信息
* 要素
    * 跨平台: Linux, Windows
    * QML: 类似HTML, 可用JS交互, 用CSS操纵样式. 

* .pro文件
    * `LIBS += -L路径 -l库名`: 添加库. 对于系统库, 在QT已设好环境变量的情形中, 则不需要`-L路径`
    * `CONFIG += console thread`: 在运行程序时打开控制台窗口. 

* 文件目录
    * .pro文件: 项目文件
    * .h文件和.cpp文件一般一一对应, 前者声明, 后者实现 

* 使用技巧
    * `alt + enter`: 在头文件声明函数后, 通过此快捷键可在对应的cpp文件中添加函数定义. 

## 环境配置
* QTCreator远程调试
    * windows
        * 调试机
            * 把`QTCreator\lib\qtcreatorcdbext64`文件夹拷贝到调试机, 将环境变量`_NT_DEBUGGER_EXTENSION_PATH`设为该文件路径. 
            * 环境变量`_NT_SYMBOL_PATH`也可以设一下, 这个是cdb的符号查找路径. cdb命令行的用法同windbg. 
            * 把项目生成的exe和pdb文件都拷贝到调试机
        * 启动调试
            * 在调试机中运行cdb启动调试服务器: `cdb.exe -server tcp:port=999 myTest.exe`
            * 在开发机的QTCreator中, 选择 `调试` -> `开始调试` -> `挂接到一个CDB会话`, 输入`tcp:server=192.168.233.128, port=999`, 其中IP地址和端口号都是调试机的cdb服务的. 
        * 调试过程
            * 要在qtcreator中打断点, 需要先在调试机的cdb中`ctrl + c`中断, 然后在qtcreator的源文件中打断点. 目前发现在qtcreator的变量窗口中不显示变量, 只能在cdb中使用命令来查询. 

## 编程
* 控件
    * 父类: `QWidget`
    * 接口
        * `setData`
    * `QMainWindow`: 自带工具栏, 菜单栏, 状态栏
        * QT Creator生成的MainWindow主类中, 有一个`ui`成员. 在成员函数中, 可直接用`ui->myWidgetName`的方式, 通过使用给组件命的名称, 获得组件的指针. 
    * `QDialog`: 
    * `QButton`: 
        * 示例: 
            ```cpp
            QWidget widget; // 添加窗口
            QPushButton But("按钮控件",&widget); // 定义一个按钮, 它位于 widget 窗口中
            But.setGeometry(10,10,100,50); // 设置按钮的位置和尺寸
            ```
    * `QTableWidget`: 表格组件
        * 行号从0开始. `QTableWidgetItem::row()`, `QTableWidget::selectRow(int rowNum)` 等函数都基于此前提. 
        * 示例: 
            ```cpp
            QTableWidget qTableWidget; 
            int rowNum = qTableWidget.rowCount(); // 获取当前行数
            qTableWidget.clearContents(); // 清空表格内容
            qTableWidget.setRowCount(0); // 清空表格行

            qTableWidget.insertRow(rowNum); // 在第rowNum行前插入新行. 若参数大于当前表格最大行号, 则在表格末尾插入. 这里的写法就是末尾插入. 
            QTableWidgetItem* pQTableWidgetItem = new QTableWidgetItem(); 
            ```
    * `QTreeWidget`: 树组件
        * 示例: 
            ```cpp
            QTreeWidget qTreeWidget; 
            ```

* 事件
    * 一个 Qt 界面程序要想接收事件, main() 函数中就必须调用 exec() 函数, 它的功能就是使程序能够持续不断地接收各种事件. 

* 信号和槽机制
    * 信号函数
        * 如, "按钮被按下"这个信号可以用`clicked`函数表示
        * 用`signals`关键字修饰
        * 只需声明, 无需定义
    * 槽函数
        * 对信号作出响应的函数
        * 如, "窗口关闭"这个槽可以用`close`函数表示
        * 用 `public slots`, `protected slots` 或者 `private slots` 修饰
        * 需声明和定义
    * `connect(&But, SIGNAL(clicked()), &widget, SLOT(close()));` 将But按钮的信号函数clicked和widget窗口的槽函数close关联起来. 
        * 现在(QT5以后)不用SIGNAL和SLOT宏, 改成如`&QButton::clicked`这样的. 
    * 在程序中触发信号: `emit mySignalFunc();` `mySignalFunc`是本类中一个信号成员函数. 

* 线程
    * 使用事件循环
        1. 子类化QThread
        2. 重载run, 在其中调用`QThread::exec()`方法
        3. 相关成员函数:
            * `start`: 启动
            * `quit`: 
            * `wait`: 

* 数据
    * `QString`
        ```cpp
        QString str;
        str.sprintf("%d", 1); // 格式化字符

        QString s = "hello";

        char *s = "hello";
        QString(s);

        QString s2 = s + "\n"; // 拼接字符串

        QString::number(1);

        QString::fromWCharArray(宽字符数组);
        ```

    * `QVariant`: 在组件上保存数据和传输数据时用该类
        ```cpp
        // 自定义的结构体数据
        struct MyStruct {
            int id; 
        }
        Q_DECLARE_METATYPE(MyStruct)

        // 保存结构体数据到组件
        MyStruct ms = {0};
        pMyWidget->setData(0, QT::UserRole, QVariant::fromValue(ms)); // 一参事数据的索引

        // 取回数据
        MyStruct ms2 = pMyWidget->data(0, QT::UserRole).value<MyStruct>();
            ```
    
    * `QVariantList`: 该列表类型可以保存`QVariant`类型
        ```cpp
        QVariantList qvList;
        qvList.append();
        ```

* 问题
    * 在另一个线程中动态添加新建的控件时, 新控件要以new的形式创建, 不能是局部作用域中的变量. 
