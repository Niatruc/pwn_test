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

# winsock
## 一个简易tcp服务
```cpp
#include<iostream.h>
#include<winsock2.h>
#pragma comment(lib, "ws2_32.lib")
void msg_display(char * buf)
{
	char msg[200];
	strcpy(msg,buf);// overflow here, copy 0x200 to 200
	cout<<"********************"<<endl;
	cout<<"received:"<<endl;
	cout<<msg<<endl;
}
void main()
{
	int sock,msgsock,lenth,receive_len;
	struct sockaddr_in sock_server,sock_client;
	char buf[0x200]; //noticed it is 0x200
	
	WSADATA wsa;
	WSAStartup(MAKEWORD(1,1),&wsa);
	if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
	{
		cout<<sock<<"socket creating error!"<<endl;
		exit(1);
	}
	sock_server.sin_family=AF_INET;
	sock_server.sin_port=htons(7777);
	sock_server.sin_addr.s_addr=htonl(INADDR_ANY);

	char host_name[MAXBYTE];
	gethostname(host_name, MAXBYTE); // 获取主机名称
	cout<<host_name<<endl;
	hostent *lv_pHostent;
	lv_pHostent = (hostent *)malloc(sizeof(hostent));
	if( NULL == (lv_pHostent = gethostbyname(host_name)))
	{
		printf("get Hosrname Fail \n");
		return ;
	}
	// cout<<lv_pHostent<<endl;
	
	memcpy(&sock_server.sin_addr.S_un.S_addr, 
		lv_pHostent->h_addr_list[0], lv_pHostent->h_length);
	cout<<inet_ntoa(sock_server.sin_addr)<<endl;

	if(bind(sock,(struct sockaddr*)&sock_server,sizeof(sock_server)))
	{
		cout<<"binging stream socket error!"<<endl;
	}
	cout<<"**************************************"<<endl;
	cout<<"     exploit target server 1.0	   "<<endl;
	cout<<"**************************************"<<endl;
	listen(sock,4);
	lenth=sizeof(struct sockaddr);
	do{
		msgsock=accept(sock,(struct sockaddr*)&sock_client,(int*)&lenth);
		if(msgsock==-1)
		{
			cout<<"accept error!"<<endl;
			break;
		}
		else 
			do
			{
				memset(buf,0,sizeof(buf));
				if((receive_len=recv(msgsock,buf,sizeof(buf),0))<0)
				{
					cout<<"reading stream message erro!"<<endl;
					receive_len=0; 
				}
				msg_display(buf);//trigged the overflow
			}while(receive_len);
			closesocket(msgsock);
	}while(1);
	WSACleanup();
}
```

* 问题
    * `‘inet_addr’: Use inet_pton() or InetPton() instead or define _WINSOCK_DEPRECATED_NO_WARNINGS to disable deprecated API warnings libharmorobotservice`
        * 方法一: 换用新函数`inet_pton`. 需要导入头文件`WS2tcpip.h`
        * 方法二: 工程属性 -> c/c++ -> sdl检查, 改为否

# powershell
* 管道: 命名管道的所有实例拥有相同的名称, 但是每个实例都有其自己的缓冲区和句柄, 用来为不同客户端通许提供独立的管道. 
    * 列出当前计算机所有命名管道: 
        * V3以下版本: `[System.IO.Directory]::GetFiles("\\.\\pipe\\")`
        * V3以上: `Get-ChildItem \\.\pipe\`

# 注册表
* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`中的Debugger键: 可以设置系统默认调试器, 如: `"C:\debuggers\windbg.exe" -p %ld -e %ld -g`
# PE文件
* VA和RVA
    * 参考: https://www.loidair.com/2018/02/13/binary-basic-one/
    * VA = Image Base + RVA

# svchost
* svchost.exe根据注册表项`HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Svchost`下面的键值分组管理DLL申请的服务, 每一键值对应一个独立的Svchost.exe进程. 
* `tasklist /svc`: 可以显示每个进程主持的服务
* `tasklist /M`: 可以显示每个进程用的模块(dll)

## 一些方法
* 重命名文件卡死的解决方法(以及删文件时卡在99%很长时间)
    * `sfc /scannow`: 系统会开始扫描受损的文件然后修复. 参考: https://www.bilibili.com/read/cv8178838

* win10和winxp共享文件夹
    * win10中, `控制面板` -> `程序` -> `启用或关闭windows功能` -> `SMB 1.0/CIFS 文件共享支持,` 勾选. 

* 查看和设置cmd的编码设置: `chcp`, `chcp <编码代号>`
    * 936: gbk2312
    * 65001: utf-8

* 没有`gpedit.msc`
    * 运行`mmc`, 然后如下添加`IP安全策略管理`

    <img alt="" src="./pic/windows_mmc.jpg" width="40%" height="40%">
