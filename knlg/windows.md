# MFC
* 项目类型
    * 基于对话框
    * 单文档: 文本编辑器 
    * 多文档: word
* 消息映射
    * 事件 -> 消息 -> 消息处理函数
    * 双击控件, 添加或跳转到消息处理函数. 也可右键添加. 也可在控件属性窗里面找到事件名并添加.
    * `BEGIN_MESSAGE_MAP宏`: 将消息处理函数添加到一个全局映射中w
    * 右键控件 -> 添加变量, 类别可选"值". 完成之后会在对话框类中添加一个成员变量, 空间的值存于其中.
    * `UpdataData(TRUE);`: 调用该函数后, 控件中的值才同步到成员变量中. `FALSE`则从程序更新到界面.
* 控件
    * CLabel
    * CEdit
        * 若要文本能换行:
            * 换行符是"\r\n"
            * `Mutilines`, `Want return`, `Vertical Scroll`设为true
    * CCheckbox
    * CRadiobox
    * CListctrl
    * CTabctrl
    * CRadioButton
        * Group属性设为true
        * 最后一个选项的下一个控件的Group属性也要设为true
        * 变量类型设为int, 后面设置最小值和最大值
    * CCombobox
        * 在data属性初始化下拉框数据, 每一项用分号隔开
        * 代码
            ```cpp
            CComboBox *pCombo = (CComboBox *)GetDlgItem(IDC_COMBO_TEST1); // 拿到控件指针
            pCombo->InsertString(1, _T("台湾")); // 插入数据
            pCombo->SetCurSel(1); // 设置当前选中行
            Ctring szProvince;
            pCombo->GetLBText(pCombo->GetCurSel(), szProvince); // 获取当前选中的项的文本
            ```
    * CListControl: 表格
        * view属性改为report
        * 代码
            ```cpp
            // 插入列
            m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT);
            m_listCtrl.InsertColumn(0, _T("列1"), LVCFMT_LEFT, 85);
            m_listCtrl.InsertColumn(1, _T("列2"), LVCFMT_LEFT, 85);
            m_listCtrl.InsertColumn(2, _T("列3"), LVCFMT_LEFT, 85);

            // 插入行
            int iLine = m_listCtrl.GetItemCount();
            m_listCtrl.InsertItem(iLine, _T("值1"));
            m_listCtrl.SetItemText(iLine, 1, _T("值2"));
            m_listCtrl.SetItemText(iLine, 2, _T("值3"));

            // 清空列表
            while (m_listCtrl.DeleteItem(0)) ;

            // 左键选中行
            // 在对选中行事件NM_CLICK的处理中:
            int istat = m_listCtrl.GetSelectionMark();

            // 按列排序
            // 定义排序函数, 要把它声明为静态, m_sortColumn和m_bAs也都声明为静态变量
            int CALLBACK CMyMFCDlg::SortByColumn(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
                int iCompRes;
                CListCtrl* pListCtrl = (CListCtrl*)lParamSort;
                CString szComp1 = pListCtrl->GetItemText(lParam1, m_sortColumn);
                CString szComp2 = pListCtrl->GetItemText(lParam2, m_sortColumn);

                switch (m_sortColumn) {
                default:
                    iCompRes = szComp1.Compare(szComp2);
                    break;
                }
                iCompRes = m_bAs ? iCompRes : -iCompRes;
                return iCompRes;
            }

            // 在监听LVN_COLUMNCLICK消息的函数中:
            LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);

            NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
            m_sortColumn = pNMListView->iSubItem;
            m_bAs = !m_bAs;

            int count = m_listCtrl.GetItemCount();
            for (size_t i = 0; i < count; i++) {
                m_listCtrl.SetItemData(i, i);
            }
            m_listCtrl.SortItems((PFNLVCOMPARE)SortByColumn, (LPARAM) &m_listCtrl);
            ```
    * CMenu
        * 可作为右键弹出的菜单. 在资源视图中新增
        * 代码
            ```cpp
            // 弹出右键菜单
            CMenu m_Menu;
            m_Menu.LoadMenu(IDR_MENU1); // 加载菜单
            CMenu *nMenu = m_Menu.GetSubMenu(0); // 得到子菜单
            POINT pos;
            GetCursorPos(&pos); // 获取鼠标位置
            nMenu->TrackPopupMenu(TPM_LEFTALIGN, pos.x, pos.y, this);
            ```
* 其他
    * ctrl+d 显示tab顺序
* 线程
    `AfxBeginThread(MyThreadFunction, pParam)`: 线程的入口函数声明: `UINT MyThreadFunction( LPVOID pParam )`, `pParam`是传给线程的参数.

# powershell

# PE文件
* VA和RVA
    * 参考: https://www.loidair.com/2018/02/13/binary-basic-one/
    * VA = Image Base + RVA

## 一些方法
* 重命名文件卡死的解决方法
    * `sfc /scannow`: 系统会开始扫描受损的文件然后修复. 参考: https://www.bilibili.com/read/cv8178838

* win10和winxp共享文件夹
    * win10中, `控制面板` -> `程序` -> `启用或关闭windows功能` -> `SMB 1.0/CIFS 文件共享支持,` 勾选. 

* 查看和设置cmd的编码设置: `chcp`, `chcp <编码代号>`
    * 936: gbk2312
    * 65001: utf-8