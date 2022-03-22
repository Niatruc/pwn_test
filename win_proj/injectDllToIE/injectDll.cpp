#include <stdio.h>
#include <windows.h>
#pragma comment (lib, "Advapi32.lib")
// #pragma comment (lib, "Advapi64.lib")

HINSTANCE hInst;

BOOL AddDebugPrivilege(void)
{

    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;

    if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&luid))
    {
        printf("LookupPrivilegeValue error\n");
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid=luid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;

    if(!OpenProcessToken(GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES,&hToken))
    {
        printf("OpenProcessToken Error\n");
        return FALSE;
    }

    if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),
    (PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges Error\n");
        return FALSE;
    }
    return TRUE;
} 

int InjectDll( HANDLE hProcess )
{
	HANDLE hThread;
	char   szLibPath [_MAX_PATH];
	void*  pLibRemote = 0;	// the address (in the remote process) where
							// szLibPath will be copied to;
	DWORD  hLibModule = 0;	// base adress of loaded module (==HMODULE);

    // 用于得到LoadLibraryA函数的地址
	HMODULE hKernel32 = ::GetModuleHandle("Kernel32");

	// 得到"dllTest.dll"的完整路径
	if( !GetModuleFileName( hInst, szLibPath, _MAX_PATH) )
		return false;
	strcpy( strstr(szLibPath,"injectDll.exe"),"dllTest.dll" );


	// 1. 给szLibPath在要注入的进程中分配内存
	// 2. 将szLibPath写入分配的内存
	pLibRemote = ::VirtualAllocEx( hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE );
	if( pLibRemote == NULL )
		return false;
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, sizeof(szLibPath), NULL);

	// 将"dllTest.dll"注入进程
	hThread = ::CreateRemoteThread( hProcess, NULL, 0,	
					(LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32, "LoadLibraryA"), 
					pLibRemote, 0, NULL );
	if( hThread == NULL ) {
        int err = GetLastError();
        printf("error code: %d\n", err);
		goto JUMP;
    }

	::WaitForSingleObject( hThread, INFINITE );

	// Get handle of loaded module
	::GetExitCodeThread( hThread, &hLibModule ); // 获取线程的退出代码，非零则成功
	::CloseHandle( hThread );

JUMP:	
	::VirtualFreeEx( hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE );
	if( hLibModule == NULL ) // 线程执行失败
		return false;
	

	// 卸载注入的dll
	hThread = ::CreateRemoteThread( hProcess,
                NULL, 0,
                (LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32,"FreeLibrary"),
                (void*)hLibModule,
                 0, NULL );
	if( hThread == NULL )	// failed to unload
		return false;

	::WaitForSingleObject( hThread, INFINITE );
	::GetExitCodeThread( hThread, &hLibModule );
	::CloseHandle( hThread );

	// return value of remote FreeLibrary (=nonzero on success)
	return hLibModule;
}


int main(int argc, char const *argv[])
{
    char *pid = (char *) argv[1];
    DWORD PID = atoi(pid);
    // DWORD PID = 28352;
	printf("注入的进程: %d", PID);
    HANDLE hProcess = 
			OpenProcess(
				PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
				FALSE, PID);
    // AddDebugPrivilege();
    if (hProcess != NULL) {
        InjectDll(hProcess);
    }
    
    return 0;
}
