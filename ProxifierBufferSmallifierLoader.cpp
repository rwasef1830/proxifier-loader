#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include "DebugPrint.h"

#define DEFAULT_PATH L"ProxifierOriginal.exe"
#define HOOK_DLL L"ProxifierBufferSmallifierLoaderHook.dll"

int wmain(int argc, const wchar_t* argv[]) {
    const wchar_t** proxifierArgv = NULL;
    int proxifierArgc = 0;
    
    LPCWSTR proxifierPath = DEFAULT_PATH;
    proxifierArgc = argc - 1;
    proxifierArgv = &argv[1];
    
    if (proxifierArgc == 0)
    {
        proxifierArgv = NULL;
    }
    
    wchar_t commandLine[2048] = {0};
    wcscat_s(commandLine, 2048, proxifierPath);
    wcscat_s(commandLine, 2048, L" ");
    
    if (proxifierArgc > 0)
    {
        for (int i = 0; i < proxifierArgc; i++)
        {
            wcscat_s(commandLine, 2048, L"\"");
            wcscat_s(commandLine, 2048, proxifierArgv[i]);
            wcscat_s(commandLine, 2048, L"\" ");
        }
    }
    
     // Create the job object
    HANDLE jobObject = CreateJobObjectW(NULL, NULL);
    if (!jobObject) {
        DebugPrint(L"Error: CreateJobObjectW failed with error code %d", GetLastError());
        return 1;
    }
    
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo;
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(jobObject, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo));
    
    if (!AssignProcessToJobObject(jobObject, GetCurrentProcess())) {
        DebugPrint(L"Error: AssignProcessToJobObject failed with error code %d", GetLastError());
        return 1;
    }
    
    DebugPrint(L"%ls", commandLine);

    // Load the program to be monitored
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(
        NULL, 
        commandLine, 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED, 
        NULL, 
        NULL, 
        &si, 
        &pi))
    {
        DebugPrint(L"CreateProcess failed: %d", GetLastError());
        CloseHandle(jobObject);
        return 1;
    }

    LPVOID lpLoadLibraryW = (LPVOID)GetProcAddress(
        GetModuleHandle(L"KERNEL32.DLL"), 
        "LoadLibraryW");
    if (!lpLoadLibraryW)
    {
        DebugPrint(L"GetProcAddress failed");
        CloseHandle(jobObject);
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
        DebugPrint(L"VirtualAllocEx failed");
        CloseHandle(jobObject);
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
        DebugPrint(L"WriteProcessMemory failed");
        VirtualFreeEx(pi.hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(jobObject);
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
        DebugPrint(L"CreateRemoteThread failed");
        VirtualFreeEx(pi.hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(jobObject);
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