#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <wchar.h>
#include <windows.h>

#define DEFAULT_PATH L"Proxifier.exe"
#define HOOK_DLL L"ProxifierBufferSmallifierLoaderHook.dll"

int wmain(int argc, const wchar_t* argv[]) {
    LPCWSTR proxifierPath;
    if (argc < 2) {
        proxifierPath = DEFAULT_PATH;
    }
    else {
        proxifierPath = argv[1];
    }
    
    int pathLength = wcslen(proxifierPath);
    wchar_t proxifierPathCopy[pathLength];
    wcscpy(proxifierPathCopy, proxifierPath);
    
    wprintf(L"%ls\n", proxifierPathCopy);

    // Load the program to be monitored
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(
        NULL, 
        proxifierPathCopy, 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED, 
        NULL, 
        NULL, 
        &si, 
        &pi))
    {
        wprintf(L"CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    LPVOID lpLoadLibraryW = (LPVOID)GetProcAddress(
        GetModuleHandle(L"KERNEL32.DLL"), 
        "LoadLibraryW");
    if (!lpLoadLibraryW)
    {
        wprintf(L"GetProcAddress failed\n");
        CloseHandle(pi.hProcess);
        return 1;
    }
    
    int nLength = wcslen(HOOK_DLL) * sizeof(WCHAR);
    
    LPVOID lpRemoteString = VirtualAllocEx(
        pi.hProcess, 
        NULL, 
        nLength + 1, 
        MEM_COMMIT, 
        PAGE_READWRITE);
    if (!lpRemoteString)
    {
        wprintf(L"VirtualAllocEx failed\n");
        CloseHandle(pi.hProcess);
        return 1;
    }
    
    if (!WriteProcessMemory(
        pi.hProcess, 
        lpRemoteString, 
        HOOK_DLL, 
        nLength, 
        NULL)) 
    {
        wprintf(L"WriteProcessMemory failed\n");
        VirtualFreeEx(pi.hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        return 1;
    }
    
    HANDLE hThread = CreateRemoteThread(
        pi.hProcess, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)lpLoadLibraryW, 
        lpRemoteString, 
        0, 
        NULL);
    if (!hThread)
    {
        wprintf(L"CreateRemoteThread failed\n");
        VirtualFreeEx(pi.hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, 4000);

    // Resume the program
    ResumeThread(pi.hThread);

    // Wait for the program to terminate
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Release resources
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}