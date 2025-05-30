* unicode查询: https://symbl.cc/cn/unicode/
* ansi转义序列: 
    * [ANSI Escape Sequences](https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797)
    * [ANSI escape code](https://en.wikipedia.org/wiki/ANSI_escape_code)
    * [ANSI转义序列](https://zh.wikipedia.org/zh-cn/ANSI%E8%BD%AC%E4%B9%89%E5%BA%8F%E5%88%97)

# QT
## 参考
* 下载: https://download.qt.io/archive/qt/5.14/5.14.2/
* vs插件: https://download.qt.io/official_releases/vsaddin/2.8.1/qt-vsaddin-msvc2019-2.8.1-rev.06.vsix (hash: 390b0ebba8f4276f82564179f8ad2abe )
* qt存储库: https://mirrors.tuna.tsinghua.edu.cn/qt/online/qtsdkrepository/windows_x86/root/qt/
* ubuntu下支持拼音输入法: https://blog.csdn.net/qq_27278957/article/details/96912344
* 以root运行的qtcreator无法输入中文. 
* QT以root权限run/debug: https://www.cnblogs.com/liushui-sky/p/12880971.html
* 静态编译`Qt`
    * 参考: https://blog.csdn.net/GerZhouGengCheng/article/details/118305670
    * 需要先安装: 
        * python
        * `sudo apt-get install libxcb-xfixes0-dev`
* 以root运行qtcreator, 调试项目时报错
    * 在工程设置中, 将`run in terminal`的钩去掉. 
* 高版本系统开发的程序放到低版本运行: 
    * https://www.toutiao.com/article/7088346748493627917/?wid=1663733063118
* 打包
    * https://blog.csdn.net/zyhse/article/details/106381937
    * linuxdeployqt
        * https://github.com/probonopd/linuxdeployqt/blob/master/README.md
        * `linuxdeployqt Test -appimage -unsupported-allow-new-glibc`
        * `linuxdeployqt Test -appimage -unsupported-bundle-everything`
* 表格显示问题(过早, 在字符串出现空格处显示省略号)的改进: 
    * https://stackoverflow.com/questions/64198197/how-to-prevent-too-aggressive-text-elide-in-qtableview

## 信息
* 要素/特点
    * 跨平台: Linux, Windows
    * QML: 类似HTML, 可用JS交互, 用CSS操纵样式. 
    * 元对象编译器(MOC)
        * 一个预处理器, 程序编译前会先将带有Qt特性的程序转为标准C++兼容的格式. 
        * QtCore模块是QT类库的核心. 
        * 比如, 使用了信号机制的类, 都会有一个`Q_OBJECT`宏. 
    * 元对象系统
        * 三个基础
            * `QObject`类是所有使用元对象系统的类的基类. 
            * 在类的private部分声明`Q_OBJECT`, 则类可以使用元对象的特性, 包括动态属性, 信号和槽. 
            * MOC为每个`QObject`的子类提供必要的代码来实现元对象系统的特性. 
        * API
            * `QObject::metaObject()`: 返回类关联的元对象(即`QMetaObject`对象)
            * `QMetaObject::className()`: 返回类名. 
            * `QMetaObject::newInstance()`: 创建类的一个新实例. 
            * `QObject::inherits(const char* className)`: 判断一个实例是否是名为`className`的类的实例. 
            * `QObject::tr()`, `QObject::trUtf8()`: 可翻译字符串, 用于多语言界面设计. 
            * `QObject::setProperty()`, `QObject::property()`: 可通过属性名称动态设置属性和获取属性. 
            * `qobject_cast`: 动态映射, 类似于C++的`dynamic_cast`, 只是其不需要RTTI的支持, 而且可以跨越动态链接库的边界. 
                ```cpp
                QObject *obj = new QMyWidget;
                QWidget *widget = qobject_cast<QWidget *>(obj); // obj原先是指向QMyWidget类的, 将其投射为QWidget
                ```
    * 属性系统
        * 基于元对象系统实现
        * 
        ```cpp
        Q_PROPERTY(type name // 分别指明返回值类型和属性名称
            (READ getFunc [WRITE setFunc] | MEMBER memberName [(READ getFunc | WRITE setFunc)]) // MEMBER指定一个成员变量与属性关联
            [RESET resetFunc] // 指定函数, 用于设置缺省值
            [NOTIFY notifyFunc] // 设置一个信号, 属性值发生变化时, 包含该属性的对象会发送发射此信号(要设置MEMBER)
            [REVISION int]
            [DESIGNABLE bool] // 表示属性是否能在Qt Designer中可见. 默认为true
            [SCRIPTABLE bool]
            [STORED bool]
            [USER bool]
            [CONSTANT] // 表示属性值是一个常数(不能有WRITE和NOTIFY)
            [FINAL] // 表示所定义的属性不能被子类重载
        )

        // 例
        Q_PROPERTY(bool enabled READ isEnabled WRITE setEnabled)

        bool enabled;
        ```

        * 注: 
            * `NOTIFY`指定的信号只在`setProperty`时触发, 直接用等号赋值不会触发. 
    * `Q_CLASSINFO`: 
        * 可为类的元对象添加`名称-值`的附加信息, 如`Q_CLASSINFO("author", "Tom")`. 
        * 获取元信息: `QMetaObject::classInfo(int index)`, 返回`QMetaClassInfo`对象, 其中有`name()`和`value()`两个函数可用. 

* .pro文件
    * `LIBS += -L路径 -l库名`: 添加库. 对于系统库, 在QT已设好环境变量的情形中, 则不需要`-L路径`
    * `CONFIG += console thread`: 在运行程序时打开控制台窗口. 
    * `CONFIG += exceptions_off`: 可屏蔽系统异常引起的弹框. 在使用windows的`__try__except`时有用. 
    * `QMAKE_CFLAGS += -DMYFLAG1`: 表示给`gcc`编译器添加`-DMYFLAG1`选项. 
    * `QMAKE_CXXFLAGS += -DMYFLAG1`: 表示给`g++`编译器添加`-DMYFLAG1`选项. 
    * `QMAKE_LFLAGS += /MANIFESTUAC:\"level=\'requireAdministrator\' uiAccess=\'false\'\"`: 运行前请求以管理员权限运行. 

* 文件目录
    * `.pro`文件: 项目文件
    * `.h`文件和`.cpp`文件一般一一对应, 前者声明, 后者实现 

* 使用技巧
    * `alt + enter`: 在头文件声明函数后, 通过此快捷键可在对应的cpp文件中添加函数定义. 
    * 为Release版本添加调试信息: 
        * `Projects` -> `Build`, `Edit build configuration`选`Release`, 在`Build Steps`的`qmake`中, 点`Details`, 勾选`Generate separate debug info`. 
    * 静态编译
        * 需要先下载qt源码, 然后构建, 并在qtcreator的kits集中新增新构建的静态版qmake

## 环境配置
* QTCreator
    * 远程调试
        * windows
            * 调试机
                * 把`Tools\QTCreator\lib\qtcreatorcdbext64`文件夹拷贝到调试机, 将环境变量`_NT_DEBUGGER_EXTENSION_PATH`设为该文件路径. 
                * 环境变量`_NT_SYMBOL_PATH`也可以设一下, 这个是cdb的符号查找路径. cdb命令行的用法同windbg. 
                * 把项目生成的**exe和pdb文件**都拷贝到调试机. 
            * 启动调试
                * 在调试机中运行cdb启动调试服务器: `cdb.exe -server tcp:port=999 myTest.exe`
                * 在开发机的QTCreator中, 选择 `调试` -> `开始调试` -> `挂接到一个CDB会话`, 输入`tcp:server=192.168.233.128, port=999`, 其中IP地址和端口号都是调试机的cdb服务的. 
            * 调试过程
                * 要在qtcreatorr的源文件中打断点, 需要先在调试机的cdb中`ctrl + c`中断. 
                * 目前发现在qtcreator的变量窗口中不显示变量, 只能在cdb中使用命令来查询. 
    * 问题
        * 编辑器中没有解析符号, 且报错`Clang Code Model: Error: The clangbackend executable ... could not be started`: 
            * `帮助` -> `关于插件`, 把 `C++` -> `ClangCodeModel`后的勾去掉, 重启qtcreator. 

## 编程
* 控件

    <img alt="" src="./pic/qt_window.png" width="80%" height="80%">

    * `QObject`: 
        * `deleteLater`: 会在对象的所有事件处理完后再释放对象. **应该使用该方法, 而非直接用delete释放对象.**
            * `deleteLater` 后依然可以访问和操作对象, 直到再次回到事件循环. 
    * `QWidget`: 所有控件的父类
        * 窗口关闭处理
            * 须在子窗口的构造函数中加一句`setAttribute(Qt::WA_DeleteOnClose)`, 这样关闭子窗口时才会执行析构函数. 
            * `void closeEvent(QCloseEvent *event)`: 实现该虚函数, 以捕获窗口关闭事件
                * `event->ignore()`: 执行该句, 则窗口不会关闭. 
        * 接口
            * `grab(const QRect &rectangle = QRect(QPoint(0, 0), QSize(-1, -1)))`: 将控件渲染成一张图, 作为`QPixmap`实例
            * `setParent(parent)`
                * `setParent(Null)`: 将控件从其父组件移除, 但对象不会被删除, 需要调用`deleteLater`
            * `setFocusPolicy(Qt::ClickFocus)`: 设置控件在点击时获取焦点. 
            * `show`: 在new一个窗口后, 调用该方法以显示窗口. 
            * `setWindowModality(type)`: 设置模态, 以禁止其他界面响应. 
                * `type`: 
                    * `Qt::NonModal`
                    * `Qt::WindowModal`: 阻塞父窗口, 父窗口的父窗口, 兄弟窗口. 
                    * `Qt::ApplicationModal`
            * `setVisible(bool)`: 设置组件是否可见. 
            * 在组件中绑定数据
                * `Q_DECLARE_METATYPE(<数据类型>)`: 必须先将相关数据类型(包括结构体)用此宏做声明, 才能使用`setData`. 
                * `setData(int role, const QVariant &value)`: 绑定数据
                * `setData(int column, int role, const QVariant &value)`: 绑定数据(`QTableWidgetItem`和`QTreeWidgetItem`)
                * `data(int role)`: 获取数据
                * `data(int column, int role)`: 获取数据(`QTableWidgetItem`和`QTreeWidgetItem`)
    * `QLayout`: 
        * `QSplitter`: 分割器
            ```cpp
            // 设置初始化时两侧窗口占比
            ui->mySplitter->setStretchFactor(0, 1); // 0表示第0个格子. 占比为1
            ui->mySplitter->setStretchFactor(1, 2); // 1表示第1个格子. 占比为2
            ```
        * `QHBoxLayout`
        * `QVBoxLayout`
        * 动态添加控件: 可以通过调用`addWidget`方法往一个layout控件中动态添加控件(添加到尾部), 也可以用`insertwidget(index, widget)`. 
        * 让QWidget中的控件紧凑: 加一个`QSpacerItem`: `layout->addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Expanding))`
        * 遍历layout下的组件不能用`children`方法, 应该这样: 
            ```cpp
                for (int i = 0; i < layout->count(); i++) { 
                    QLayoutItem *item = layout->itemAt(i);
                    if (item) { 
                        QWidget *widget = item->widget(); // 获取组件
                    }
                }
            ```
        * 踩坑
            * 在designer中, 需要先往一个widget中添加组件, 然后才能设置layout. 
    * 容器
        * `QScrollArea`
            * 在容器中内容长于容器时(比如设置了里面组件的最小高度大于容器高度时), 将显示滚动条. 
        * `QDockWidget`
            * 方法
                * `setFloating(true)`: 设置窗口为分离
                * `mainwindow->addDockWidget(Qt::LeftDockWidgetArea, myDock)`: 将一个`QDockWidget`放到`mainwindow`中
    * `QMainWindow`: 自带工具栏, 菜单栏, 状态栏
        * `QT Creator`生成的`MainWindow`主类中, 有一个`ui`成员. 在成员函数中, 可直接用`ui->myWidgetName`的方式, 通过使用给组件命的名称, 获得组件的指针. 
    * `QDialog`: 
        * 信号
            * `rejected`: 按`ESC`时触发
        * 方法
            * `QDialog::show()`: 非模态, 非阻塞的. 
            * `QDialog::exec()`: 模态, 阻塞, 整个系统阻塞掉. 
            * `QDialog::open()`: 窗口模态, 只会阻塞一个窗口. 
    * 右键菜单: 
        ```cpp
            this->setContextMenuPolicy(Qt::CustomContextMenu);
            tabMenu = new QMenu(ui->myTable); // 指定在ui->myTable右键时弹出菜单

                QAction *act1 = new QAction("do sth", this);
                tabMenu->addAction(act1);
                connect(act1, SIGNAL(triggered(bool)), this, SLOT(handel_act1)); // 绑定slot

                // 选项组
                auto actGrp = new QActionGroup(ui->myTable);
                actGrp->setExclusive(true); // 设为单选

                    QAction *act2 = new QAction("do sth 2", this);
                    act2->setCheckable(true); // 设为可勾选. 此时, 其triggered信号的bool类型参数可用于判断该项是否为勾选. 
                    actGrp->addAction(act2); // 加入到组
                    tabMenu->addAction(act2); // 加入到菜单

                    QAction *act3 = new QAction("do sth 3", this);
                    act3>setCheckable(true);
                    actGrp->addAction(act3);
                    tabMenu->addAction(act3);

                connect(actGrp, &QActionGroup::triggered, this, [=](){

                });

            connect(ui->myTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(my_show_tabMenu(QPoint))); // 绑定slot, 以在点击位置弹出菜单

            void MyWidget::my_show_tabMenu(QPoint) {
                tabMenu->exec(QCursor::pos());
            }
        ``` 
    * 按钮
        * `QPushButton`: 
            * 示例: 
                ```cpp
                    QWidget widget; // 添加窗口
                    QPushButton But("按钮控件",&widget); // 定义一个按钮, 它位于 widget 窗口中
                    But.setGeometry(10, 10, 100, 50); // 设置按钮的位置和尺寸
                ```
        * `QToolButton`: 
            * 特性
                * 常在点击后执行某个任务. 
                * 通常不是显示文字, 而是显示图标. 
        * `QRadioButton`: 单选按钮
            ```cpp
                // 将单选按钮添加到组中
                auto radioGrp = new QButtonGroup(this);
                radioGrp->addButton(ui->rBtn0, 0);
                radioGrp->addButton(ui->rBtn1, 1);
            ```
        * `QCheckBox`: 
            * 信号
                * `stateChanged(int)`
            * 方法
                * `setCheckState(state)`: 设为选中状态(`Unchecked`, `PartiallyChecked`, `Checked`)
                * `isChecked()`: 判断是否选中
    * 单元组件
        * `QTableWidget`: 表格组件
            * 要点
                * 行号从0开始. `QTableWidgetItem::row()`, `QTableWidget::selectRow(int rowNum)` 等函数都基于此前提. 
                * cell和item: cell表示单元格所在的这个空格, item才是单元格内容. 
            * 属性
                * `sortingEnabled`: 设置是否可按列排序.  
                * `Header`: 可设置行高, 列宽. 
                    * `horizontalHeaderStretchLastSection`: 设置最后一列宽度占满表格. 对于单列表格有用. 
            * 信号
                * `currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn)`: 当选中了新的单元格时, 触发该信号. 
            * 示例: 
                ```cpp
                // 解决点击表格时表头变粗的问题
                ui->myTableWidget->setHighlightSections(false);

                // QTableWidget ui->myTableWidget; 
                int rowNum = ui->myTableWidget->rowCount(); // 获取当前行数
                ui->myTableWidget->clearContents(); // 清空表格内容
                ui->myTableWidget->setRowCount(0); // 清空表格行
                QModelIndexList indexList = ui->myTableWidget->selectionModel()->selectedRows(); // 获取所有选中的行

                // 设置列宽
                ui->myTableWidget->horizontalHeader()->resizeSection(0, 150); // 设置第0列的宽度为150
                ui->myTableWidget->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents); // 设置列宽按内容变化. 
                    // 其他模式
                    //   QHeaderView::Fixed, 固定
                    //   QHeaderView::Stretch, 拉满, 等宽
                    //   QHeaderView::Custom
                    //   QHeaderView::Interactive
                ui->myTableWidget->horizontalHeader()->setStretchLastSection(true) // 让最后一列填满表格

                ui->myTableWidget->insertRow(rowNum); // 在第rowNum行前插入新行. 若参数大于当前表格最大行号, 则在表格末尾插入. 这里的写法就是末尾插入. 

                // 在单元格插入新的item
                QTableWidgetItem* pQTableWidgetItem1 = new QTableWidgetItem(); 
                ui->myTableWidget->setItem(rowNum, 0, pQTableWidgetItem1); // 在第0列插入

                // 删除item
                auto item = ui->myTableWidget->takeItem(rowNum, colNum)
                delete item

                ui->myTableWidget->setCellWidget(row, col, myButton); // 在列中插入控件(比如按钮)
                ui->myTableWidget->cellWidget(row, col); // 获取控件
                ui->myTableWidget->removeCellWidget(row, col); // 删除单元格中的控件

                pQTableWidgetItem1->setData(Qt::DisplayRole, 12); // 为单元格设置数据12. 选用DisplayRole, 可以让列在排序按数字而非字符序. 
                pQTableWidgetItem1->setTextAlignment(Qt::AlignRight); // 设置文本右对齐

                // 清空表格
                ui->myTableWidget->clearContents(); // 不会去除表头
                ui->myTableWidget->setRowCount(0);

                // 去除行号
                QHeaderView *h = ui->myTableWidget->verticalHeader();
                h->setHidden(true);

                ```
            * 问题
                * 排序后, 对item获取的行号可能不正确. 
                    * 解决方法: 每次`setItem`前先关闭排序功能. 
                    ```cpp
                    ui->myTableWidget->setSortingEnabled(false);
                    ... // 调用setItem插入单元
                    ui->myTableWidget->setSortingEnabled(false);
                ```
        * `QTreeWidget`: 树组件
        * 示例: 
            ```cpp
            QTreeWidget* qTree; 
            QTreeWidgetItem* qItem; 

            qTree->setColumnCount(2) // 设置列数. 如果在设计器中给数组件设计了多列, 需要显式调用此函数, 否则只显示一列. 
            qTree->headerItem()->text(0) // 获取第0列的名称

            // 设置列头名称
            QStringList headerLabels;
            headerLabels.push_back(tr("text1"));
            headerLabels.push_back(tr("text2"));
            qTree->setHeaderLabels(headerLabels)

            qTree->resizeColumnToContents(0) // 使列的宽度适应内容. 参数表示第几列

            qItem->setFlags(Qt.ItemIsEnabled | Qt.ItemIsEditable)  // 设为可编辑

            qTree->currentItem() // 获取当前选中的节点
            qTree->currentColumn() // 当前选中了节点的哪一列

            qDeleteAll(qTree.takeChildren()); // 清空节点下所有子节点
            qItem->setChildIndicate(QTreeWidgetItem::ShowIndicator);

            qItem->child(i); // 获取第i个子节点
            qItem->parent(); // 获取父节点
            qTree->topLevelItem(i); // 获取第i个顶层节点

            auto newItem = new QTreeWidgetItem(qItem); // 在qItem下创建新的子节点
            qTree->addTopLevelItem(new QTreeWidgetItem); // 

            ui->myTreewidget->editItem(qItem, 0);
            
            qTree->setExpanded(true); // 展开树

            qTree->sortItems(2, Qt::SortOrder::AscendingOrder); // 表示按第二列的值排序
            
            // 遍历
            QTreeWidgetItemIterator it(qTree);
            while (*it) {
                it->text(0);
                ...
                it++;
            }
            ```
    * 输入组件
        * `QLineEdit`: 文本框(一行)
            * 信号
                * `textEdited(const QString &text)`: 文本框有编辑动作时触发. 
                * `textChanged(const QString &text)`: 文本框内容改变时触发. 
                * `editingFinished`: 文本框发生了更改, 并且失去焦点时触发. 
                * `cursorPositionChanged(pre_pos, cur_pos)`: 光标位置改变时触发
            * 方法
                * `setInputMask("000.000.000.000; ")`: 设置输入格式为点分十进制字符串. 
                    * 参考: https://juejin.cn/post/7154316626676940813
                * `setValidator(new QRegExpValidator(QRegExp("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b")))`: 同上, 但是更严谨. 
        * `QCombobox`: 下拉框
            * 信号: 
                * `activated(int)`: 选中任何item时
                * `currentIndexChanged`: 选项发生改变时
                * `currentTextChanged`: 文本发生改变时
                * `editTextChanged`: 编辑文本时
            * 方法
                * `setCurrentText(const QString &text)`: 如果列表中有匹配的文本, 则`currentIndex`会被设置为相应的索引. 
                * `addItem(const QString & text, const QVariant &userData = QVariant())`
                * `addItems(const QStringList & texts)`
                * 设置placeholder: `lineEdit()->setPlaceholderText(text)`
        * `QTextEdit`: 文本框(多行)
            * 信号
                * `copyAvailable(bool yes)`: 当选中或取消选中文本时触发. 
            * 方法
                * `setOverwriteMode(True)`: 设置编辑器为覆盖模式. (相当于按下`Insert`)
                * `setMouseTracking(True)`: 设置追踪鼠标, 这样才能持续捕获`MouseMove`事件. (为了提升文本编辑器的性能, 默认为`False`)
                    * 注: `MouseMove`事件要在文本框的`viewport`中捕获处理. 
                * 追加内容
                    * `append(sth)`: 追加内容(会换行)
                    * `insertPlainText(sth)`, `insertHtml(sth)`: 不会换行
                * 滚动到底部
                    * `MyTextEdit.verticalScrollBar()->setValue(MyTextEdit.verticalScrollBar()->maximum());`
            * 光标
                * 获取光标: 
                    * `tc = myTextEdit->textCursor()`
                    * `tc = myTextEdit->cursorForPosition(pos)`: 按位置获取光标. 
                * `QTextCursor`
                    * 注: 
                        * 直接对`tc`调用改变位置的方法, `MyTextEdit`的光标不会跟着变化, 要调用`setTextCursor`方法后才会变化. 
                    * 方法: 
                        * 操作内容
                            * `insertText(sth)`: 光标处插入内容
                            * `insertHtml(sth)`: 光标处插入html文本
                            * `deletePreviousChar()`: 删除光标前一个字符
                        * 选区
                            * `hasSelection()`: 判断是否有选中
                            * `clearSelection()`: 取消选中
                            * `selectionStart()`: 获取选区开头的下标
                        * 位置
                            * `position()`: 获取光标位置(一个字符右侧的光标位置数值: 从行头到该字符的字符总数)
                            * `blockNumber()`: 获取光标所在行
                            * `columnNumber()`: 获取光标所在列
                            * `moveCursor(QTextCursor::End, QTextCursor::KeepAnchor)`: 将光标移到末尾. `KeepAnchor`表示会选中光标掠过的文本. 
                                * 一参的其它可选值: `PreviousCharacter`, `PreviousWord`, `PreviousBlock`等
                                * 二参的另一个可选值: `MoveAnchor`
                                * `QTextEdit`实例也有这个方法, 参数一样. 
                            * `setPosition(pos, moveMode)`: 将光标设置到`pos`位置. 二参意同`moveCursor`二参. 
                                * 每次`setPosition`后, `position()`获取的值为`setPosition`之前的光标位置. 
                                * 如果一参超过了行文本长度, 则`position()`获取的值为末尾的下标. 
                            * `selectedText()`: 获取选中的文本. 
                                * 可以前后使用两次`setPosition`(二参为`QTextCursor::KeepAnchor`), 然后通过`selectedText`获取一个范围内的文本. 
                            * `block()`: 获得光标所在行的`QTextBlock`实例
                * `myTextEdit->setTextCursor(tc)`: 在操作完光标后, 移动文本框中光标的位置
            * `QTextBlock`: 文本框中的一个块(比如一行, 注意跟`QTextLine`没关系, `QTextLine`是`QTextLayout`的东西)
                * 方法
                    * `length()`: 获取块的内容长度(包括换行符在内的格式化字符)
                    * `text()`: 获取块的内容
                    * `position()`: 获取行的第一个字符在整个文档中的位置
        * `QPlainTextEdit`: 也是文本框
            * 渲染html的性能比`QTextEdit`好. 
                * `appendHtml(sth)`: (不会换行)
            * 方法
                * `document()`: 获取`QTextDocument`实例
                    * `findBlockByLineNumber(2)`: 获取第二行的块(`QTextBlock`)
                        * `text()`: 获取行文本. 
        * `QSpinBox`: 微调框
            * 方法
                * `value()`: 获取数据
    * `QFileDialog`: 文件选择对话框
        * `QString d = QFileDialog::getExistingDirectory();`
        * `QString d = QFileDialog::getOpenFileName();`
    * `QLable`
        * 设置图标: 
            * `QMovie`: 可在`QLable`组件中设动图
                ```cpp
                    QMovie *m = new QMovie(":/image/loading.gif");
                    ui->myLable->setMoive(m);
                    movie->setScaledSize(ui->myLabel->size()); // 设置和label一样大小
                    movie->start();
                ```
    * `QScintilla`: 第三方开源编辑器
* 事件
    * 一个 Qt 界面程序要想接收事件, `main()` 函数中就必须调用 `exec` 函数, 它的功能就是使程序能够持续不断地接收各种事件. (?)
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
    * `QCoreApplication::processEvents()`: 调用该函数, 让程序处理那些还没有处理的事件, 让程序保持响应. 
    * 监听在某个组件上的事件: 
        ```cpp
        ui->myTableWidget->installEventFilter(this); // 给表格安装事件处理器

        bool MainWindows::eventFilter(QObject *obj, QEvent *eve) {
            auto e = static_cast<QKeyEvent *>(eve);
            int key = e->key;
            switch (e->type()) {
                case QEvent::KeyRelease: 
                    if (e->isAutoRepeat()) // 这一行可不免长按某个键(比如方向键)时反复执行后面的可能比较耗时的代码. 
                        return false;
                    if (key == Qt::Key_up) {
                        ...
                        e.accept(); // accept以后, 父组件不会收到事件; ignore则反之
                        return true; // 阻止对事件的后续操作
                    }
                    break;
            }
        }
        ```
    * 在编码层面触发事件
        ```py
            new_key_event = QKeyEvent(QEvent.Type.KeyPress, event.key(), event.modifiers(), event.text().upper())
            QApplication.postEvent(self.parent(), new_key_event)  # 模拟按键事件(在当前函数结束后再处理此事件)
            QApplication.sendEvent(self.parent(), new_key_event)  # 模拟按键事件(立刻处理此事件, 完了再回来当前函数)
        ```
    * 拖拽(`QDrag`)
        * 参考
            * [Qt拖放(1)：拖放基本原理(QDrag类)](https://blog.csdn.net/hyongilfmmm/article/details/83238239)
            * [Drag and Drop](https://doc.qt.io/qt-6/dnd.html)
        * 注: 
            * 需要放操作的目标组件上同时处理`QDragEnterEvent`(拖动操作进入目标组件), `QDragMoveEvent`(拖动操作在目标组件上移动), `QDropEvent`(拖动操作结束), 并对事件调用`accept`. 
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
            * `Qt::AutoConnection`: 缺省值. 若发射和接收信号是同一线程, 则相当于`DirectConnection`, 否则相当于`QueuedConnection`. 
            * `Qt::DirectConnection`: 
            * `Qt::QueuedConnection`: 
            * `Qt::BlockingQueuedConnection`: 同`DirectConnection`, 但会阻塞到槽函数返回. (若发射和接收信号是同一线程, 则不可使用它, 否则会死锁)
            * `Qt::UniqueConnection`: 可以用or与上面的几个选项组合使用. 若设置了它, 当连接已存在时, `connect`会失败. 
    * 在程序中触发信号: `emit mySignalFunc();` `mySignalFunc`是本类中一个信号成员函数. 
    * `Cannot send events to objects owned by a different thread`: 在Qt中, ui的操作不能在别的线程里. 
    * 阻塞信号: `myWidget->blockSignals(true)` (设为`false`则解除阻塞)
    * 在槽函数中获取发射信号的对象: 
        ```cpp
            QObject *senderObj = sender();
            QPushButton *button = qobject_cast<QPushButton*>(senderObj);
        ```
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
            * `terminate`: (暴力)结束线程
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
    * `QThreadPool`
        * `::globalInstance()`: 全局`QThreadPool`对象. 
    * `QRunnable`
        * 需要借助`QThreadPool`启动. 
    * 线程同步
        * 使用`QWaitCondition`和`QMutex`
            ```cpp
            // 主线程
            mutex.lock();
            Send(&packet);
            condition.wait(&mutex); // 会阻塞
            if (m_receivedPacket) {
                HandlePacket(m_receivedPacket); // 另一线程传来回包
            }
            mutex.unlock();

            // 通信线程
            m_receivedPacket = ParsePacket(buffer);  // 将接收的数据解析成包
            mutex.lock();
            condition.wakeAll();
            mutex.unlock();
            ```

            * `QWaitCondition::wait(QMutex* mutex)`: 会阻塞线程, 直到调用`wakeAll`或`wakeOne`. 官方说法, `wait`会释放`mutex`并作等待. 此外, `mutex`会"返回到相同的锁定状态"(可能是指又返回到lock状态). 这个函数做的工作是从锁定状态到等待状态的原子转换. 
    * 注意
        * 启动一个QThread子线程, 并在子线程中调用主线程生成的组件的渲染函数(如, 对`QTextEdit`组件调用`append`函数), 会导致程序崩溃退出(`0xC0000005`)
* 进程(`QProces`)
    ```py
        process = QProcess()
        process.setProcessChannelMode(QProcess.MergedChannels)  # 使进程的stdout和stderr数据都使用标准输出通道
        process.setWorkingDirectory("/work_dir")  # 设置工作目录
        process.readyReadStandardOutput.connect(__process_output)  # stdout有数据时会触发`readyReadStandardOutput`信号
        process.start("test1", ["./data1", "./data2"])

        def __apply_ansi_colors(text):  # 将终端颜色代码转为html颜色标签
            code_color_map = {
                COLOR.YELLOW: "yellow",
                COLOR.BLUE: "blue",
                COLOR.MAGENTA: "red",
                COLOR.CRIMSON: "crimson",
                COLOR.RED: "red",
                COLOR.DEFAULT: "",
            }
            ptn = r"(\033\[[0-9]*m)"
            ft = re.findall(ptn, text)
            for t in ft:
                if t == "\033[39m":
                    text = text.replace(t, "</font>")
                else:
                    text = text.replace(t, f"<font color='{code_color_map.get(t, "")}'>")
            text = text.replace("\n", "<br>")
            return text

        def __process_output():  # 处理stdout数据
            data = process.readAllStandardOutput()
            if data:
                decoded_data = data.data().decode() # 字节数据解码为字符串
                colored_data = __apply_ansi_colors(decoded_data)
                cursor = my_plainTextEdit.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.insertHtml(colored_data)
                my_plainTextEdit.ensureCursorVisible()
    ```
* 数据
    * `QString`
        ```cpp
        QString str;
        QString s = "hello";

        str.sprintf("%d", 1); // 格式化字符(旧写法)
        str = QString::asprintf("%d", 1); // 格式化字符(新写法)
        str.simplified(); // 去除首尾空格
        str.mid(pos, len); // 截取字符串, 从pos位置开始, 截取出len个字符
        str = s + "\n"; // 拼接字符串

        str.back(); // 取值

        str.indexOf("<sub_str>"); // 搜索

        QString::number(1);

        QString::fromWCharArray(L"宽字符串");
        QString::fromStdString;
        QString::fromStdWString;

        // 正则匹配
        QRegExp re("<pattern>")
        int pos = re.indexIn(str); // 返回匹配的位置
        ```
    * `QByteArray`: 字节数组. 
        * 数据会以'\0'结尾. 
        ```cpp
        QByteArray ary("1234");

        ary.size(); // 4
        ary.data(); // 得到指向底层数据的指针
        ary.resize(10); // 调整大小
        
        ary[0];
        ary.at(0); // 比ary[0]快, 因为它不会深拷贝. 

        ary.append("abcd"); // 结尾附加数据
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

* 文件和目录
    * 获取程序工作目录: `QDir::currentPath()`
    * 获取程序文件所在目录: `QCoreApplication::applicationDirPath()`
    * 打开文件管理器: `QDesktopServices::openUrl(QUrl(path))`
    * `QFileInfo`
        * 构造: `QFileInfo fileInfo(pathStr)`
        * `dir().path()`: 获取文件的父目录. 
    * `QDir`
        ```cpp
        QDir dir("./mydir");
        (dir.removeRecursively())

        QDir::mkdir("/xx/xxx/"); // 上级目录不存在时会创建失败
        QDir::mkpath("/xx/xxx/"); // 上级目录不存在时, 会一起创建. 目录已存在, 则直接返回true. 

        QDir::toNativeSeparators(path); // 将路径中的斜杠按当前操作系统替换为相应的路径分隔符
        ```
    * `QFile`
        * 打开方式
            |常量|注释|
            |-|-|
            |`QIODevice::ReadOnly`|以只读方式打开文件|
            |`QIODevice::WriteOnly`|只写方式|
            |`QIODevice::ReadWrite`|读写方式|
            |`QIODevice::Append`|追加模式打开，新写入文件的数据添加到文件尾部|
            |`QIODevice::Truncate`|截取方式打开文件，文件原有的内容全部被删除|
            |`QIODevice::Text`|文本方式打开文件，读取时“\n”被自动翻译为换行符|
        * 例
            ```cpp
            // 参考: https://blog.csdn.net/ligare/article/details/124494533
            QFile file("./f1");
            if(!file.open(QIODevice::Append)) {
                return 0;
            }

            // 读文件
            while(!file.atEnd()) {
                //方式1
                QByteArray array2 = file.readLine();
                qDebug() << array2;

                //方式2
                char buf[1024];
                qint64 lineLength = file.readLine(buf, sizeof(buf));
                if (lineLength != -1)
                {
                    // the line is available in buf
                    qDebug() << "行" << buf;
                }
            }
            // 方式3
            QTextStream in(&file);
                while (!in.atEnd()) {
                QString line = in.readLine();        
            }

            // 写文件
            //方式1
            QByteArray ba1 = "1236546";
            file.write(ba1);//叠加调用并不会换行
            //方式2
            QTextStream aStream(&file); //用文本流读取文件
            QString str="xsx";//叠加调用并不会换行
            aStream<< endl << str; //写入文本流,在字符的前面会换行

            ```
* 网络
    * 在`pro`文件, 加上`Qt += network`, 否则引用`QHostAddress`等库时会说找不到文件. 
    * `quint32 ipAddress = QHostAddress("192.168.1.100").toIPv4Address();`: 点分十进制字符串转IPv4地址. 
* 其他
    * 时间
        * `QDateTime::currentDateTime().toString()`: 获取当前日期
* 问题
    * 在另一个线程中动态添加新建的控件时, 新控件要以`new`的形式创建, 不能是局部作用域中的变量. 
    * `Cannot send events to objects owned by a different thread. `
    * 屏幕分辨率过大, `designer`窗口中的组件和文字都太大. 
        * 设置环境变量: `set QT_SCALE_FACTOR=0.8`, 该数字可适当缩小. (注: 如果设置为用户环境变量, 会影响到所有使用QT做图形界面的程序)