# QT
## 信息
* 要素
    * 跨平台: Linux, Windows
    * QML: 类似HTML, 可用JS交互, 用CSS操纵样式. 

* .pro文件
    * `LIBS += -L路径 -l库名`: 添加库. 对于系统库, 在QT已设好环境变量的情形中, 则不需要`-L路径`
    * `CONFIG += console thread`: 在运行程序时打开控制台窗口. 
    * `CONFIG += exceptions_off`: 可屏蔽系统异常引起的弹框. 在使用windows的`__try__except`时有用. 

* 文件目录
    * .pro文件: 项目文件
    * .h文件和.cpp文件一般一一对应, 前者声明, 后者实现 

* 使用技巧
    * `alt + enter`: 在头文件声明函数后, 通过此快捷键可在对应的cpp文件中添加函数定义. 
    * 为Release版本添加调试信息: 
        * `Projects` -> `Build`, `Edit build configuration`选`Release`, 在`Build Steps`的`qmake`中, 点`Details`, 勾选`Generate separate debug info`. 
    * 静态编译
        * 需要先下载qt源码, 然后构建, 并在qtcreator的kits集中新增新构建的静态版qmake

## 环境配置
* QTCreator远程调试
    * windows
        * 调试机
            * 把`Tools\QTCreator\lib\qtcreatorcdbext64`文件夹拷贝到调试机, 将环境变量`_NT_DEBUGGER_EXTENSION_PATH`设为该文件路径. 
            * 环境变量`_NT_SYMBOL_PATH`也可以设一下, 这个是cdb的符号查找路径. cdb命令行的用法同windbg. 
            * 把项目生成的exe和pdb文件都拷贝到调试机
        * 启动调试
            * 在调试机中运行cdb启动调试服务器: `cdb.exe -server tcp:port=999 myTest.exe`
            * 在开发机的QTCreator中, 选择 `调试` -> `开始调试` -> `挂接到一个CDB会话`, 输入`tcp:server=192.168.233.128, port=999`, 其中IP地址和端口号都是调试机的cdb服务的. 
        * 调试过程
            * 要在qtcreator中打断点, 需要先在调试机的cdb中`ctrl + c`中断, 然后在qtcreator的源文件中打断点. 目前发现在qtcreator的变量窗口中不显示变量, 只能在cdb中使用命令来查询. 

## 编程
* 控件

    <img alt="" src="./pic/qt_window.png" width="80%" height="80%">


    * 父类: `QWidget`
        * 窗口关闭处理
            * 须在子窗口的构造函数中加一句`setAttribute(Qt::WA_DeleteOnClose)`, 这样关闭子窗口时才会执行析构函数. 
            * `void closeEvent(QCloseEvent *event)`: 实现该虚函数, 以捕获窗口关闭事件
                * `event->ignore()`: 执行该句, 则窗口不会关闭. 
    * 接口
        * `show`: 在new一个窗口后, 调用该方法以显示窗口. 
        * 在组件中绑定数据
            * `Q_DECLARE_METATYPE`: 
            * `setData`: 
            * `data`: 
    * `QMainWindow`: 自带工具栏, 菜单栏, 状态栏
        * QT Creator生成的MainWindow主类中, 有一个`ui`成员. 在成员函数中, 可直接用`ui->myWidgetName`的方式, 通过使用给组件命的名称, 获得组件的指针. 
    * `QDialog`: 
    * 右键菜单: 
        ```cpp
        this->setContextMenuPolicy(Qt::CustomContextMenu);
        ``` 
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
            QTreeWidget* qTree; 
            QTreeWidgetItem* qItem; 

            qDeleteAll(qTree.takeChildren()); // 清空节点下所有子节点
            qItem->setChildIndicate(QTreeWidgetItem::ShowIndicator);
            ```
    * 输入组件
        * `QCombobox`: 下拉框
            * `setCurrentText(const QString &text)`: 如果列表中有匹配的文本, 则`currentIndex`会被设置为相应的索引. 
        * `QTextEdit`: 文本框
            * 接口
                * 追加内容
                    * `append(sth)`: 会换行
                    * `insertPlainText(sth)`, `insertHtml(sth)`: 不会换行
                * 光标
                    * `tc = textCursor()`: 获取光标
                    * `tc.insertText(sth)`: 光标处插入内容
        * `QPlainTextEdit`: 也是文本框
            * 渲染html的性能比`QTextEdit`好. 
                * `appendHtml(sth)`: 不会换行
    * `QtFileDialog`: 文件选择对话框
        * 
    * `QLable`
        * 设置图标: 
            * `QMovie`: 可在`QLable`组件中设动图
                ```cpp
                QMovie *m = new QMovie(":/image/loading.gif");
                ui->myLable->setMoive(m);
                movie->setScaledSize(ui->myLabel->size()); // 设置和label一样大小
                movie->start();
                ```
* 事件
    * 一个 Qt 界面程序要想接收事件, main() 函数中就必须调用 `exec` 函数, 它的功能就是使程序能够持续不断地接收各种事件. (?)
    * `QEventLoop`
        ```cpp
        void XXX::slot1() {
            QDialog dlg;
            dlg.show(); // 若直到这一行就结束, 则弹窗一下就关闭了
            QEventLoop loop;
            connect(&dlg, SIGNAL(finished(ini)), &loop, SLOT(quit()));
            loop.exec(QEventLoop::ExcludeUserInputEvents); // 启动事件循环, 等待弹框的finished信号
        }
        ```

* 信号和槽机制
    * 信号函数
        * 如, "按钮被按下"这个信号可以用`clicked`函数表示
        * 用`signals`关键字修饰
        * 只需声明一个函数, 无需定义
    * 槽函数
        * 对信号作出响应的函数
        * 如, "窗口关闭"这个槽可以用`close`函数表示
        * 用 `public slots`, `protected slots` 或者 `private slots` 修饰
        * 需声明和定义. 若命名为`on_<子对象名>_<事件名>`, 则无需再写一行`connect`, 因为构建的时候会自己生成. 
    * `connect(&But, SIGNAL(clicked()), &widget, SLOT(close()));` 将But按钮的信号函数clicked和widget窗口的槽函数close关联起来. 
        * 现在(QT5以后)不用SIGNAL和SLOT宏, 改成如`&QButton::clicked`这样的. 
        * 第5参数: 
            * `Qt::AutoConnection`: 若发射和接收信号是同一线程, 则相当于`DirectConnection`, 否则相当于`QueuedConnection`. 
            * `Qt::DirectConnection`: 
            * `Qt::QueuedConnection`: 
            * `Qt::BlockingQueuedConnection`: 同`DirectConnection`, 但会阻塞到槽函数返回. (若发射和接收信号是同一线程, 则不可使用它, 否则会死锁)
            * `Qt::UniqueConnection`: 可以用or与上面的几个选项组合使用. 若设置了它, 当连接已存在时, `connect`会失败. 
    * 在程序中触发信号: `emit mySignalFunc();` `mySignalFunc`是本类中一个信号成员函数. 
    * `Cannot send events to objects owned by a different thread`: 在Qt中, ui的操作不能在别的线程里. 
    * 阻塞信号: `myWidget->blockSignals(true)` (设为false则解除阻塞)
* 定时器
    * 
* 线程
    * 使用事件循环
        1. 子类化QThread
        2. 重载run, 在其中调用`QThread::exec()`方法
        3. 相关成员函数:
            * `start`: 启动
            * `quit`: 在`run`函数中调用之, 可主动结束线程. 
            * `exit`: 
            * `wait`: 
    * `QtConcurrent`: 可以以lambda的形式启动新线程. 
        ```cpp
        #include <QtConcurrent/QtConcurrent>

        int a = 10;
        QFuture future = QtConcurrent::run([&] () {
            while (a--) { 
                ... 
                emit this->mySignal(ssize_t param1); // 注意, 要在组件初始化时执行 qRegisterMetaType<ssize_t>("ssize_t"); 不然槽函数接收不到信号
            }
        });
        future.waitForFinished(); // 阻塞当前线程, 等待子线程返回结果
        ```
    * 注意
        * 启动一个QThread子线程, 并在子线程中调用主线程生成的组件的渲染函数(如, 对`QTextEdit`组件调用`append`函数), 会导致程序崩溃退出(`0xC0000005`)
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
