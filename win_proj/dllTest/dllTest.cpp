#include <stdio.h>
#include <windows.h>

void func() {
    char s[] = "abc"; // 结尾为0，刚好4字节
    printf("ahahahahaha\n");
    strcpy(s, "eeeeffff\x0c\x0c\x0c\x0c"); // 把返回地址覆盖为0x0c0c0c0c
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    func();
    return TRUE;
}