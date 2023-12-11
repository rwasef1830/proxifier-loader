#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

void DebugPrint(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    wchar_t message[1024];
    vswprintf(message, 1024, format, args);
    OutputDebugStringW(message);
}

// Function prototypes
typedef int (WSAAPI (*LPWSACONNECT)(
    SOCKET,
    const struct sockaddr FAR*,
    int,
    LPWSABUF,
    LPWSABUF,
    LPQOS,
    LPQOS));
    
typedef int (WSAAPI (*LPCONNECT)(
    SOCKET,
    const sockaddr *name,
    int namelen));
    
typedef int (WSAAPI (*LPLISTEN)(
    SOCKET,
    int));

#define BUFFER_SIZE 16384

LPWSACONNECT OriginalWSAConnect = NULL;
LPCONNECT OriginalConnect = NULL;
LPLISTEN OriginalListen = NULL;

BOOL ShouldHandleAddress(const struct sockaddr* name)
{
    if (name->sa_family != AF_INET && name->sa_family != AF_INET6)
    {
        DebugPrint(L"Ignoring unknown family %d", name->sa_family);
        return FALSE;
    }
    
    BOOL isLoopback = FALSE;
    
    // Check for the loopback address based on the address family
    if (name->sa_family == AF_INET) 
    {
        sockaddr_in* addr_in;
        addr_in = (sockaddr_in*)name;
        isLoopback = ((ntohl(addr_in->sin_addr.s_addr) & 0xFF000000) == 0x7F000000);
    } 
    else 
    {
        sockaddr_in6* addr_in6;
        addr_in6 = (sockaddr_in6*)name;
        isLoopback = IN6_IS_ADDR_LOOPBACK(&addr_in6->sin6_addr);
    }
    
    return isLoopback;
}

int WSAAPI WSAConnectHooked(
    SOCKET s,
    const struct sockaddr FAR* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS)
{
    if (ShouldHandleAddress(name))
    {
        DebugPrint(L"Hooked wsa connect to loopback! Setting send buffer to %d.", BUFFER_SIZE);
        int bufferSize = BUFFER_SIZE;
        int setsockoptError = setsockopt(
            s, 
            SOL_SOCKET, 
            SO_SNDBUF, 
            (char*)(&bufferSize), 
            sizeof(int));
        if (setsockoptError)
        {
            DebugPrint(L"Setting send buffer error %d", WSAGetLastError());
        }
    }
    else
    {
        DebugPrint(L"Hooked wsa connect! Not loopack.");
    }
    
    int result = (*OriginalWSAConnect)(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    return result;
}

int WSAAPI ConnectHooked(
    SOCKET s,
    const sockaddr *name,
    int namelen)
{
    if (ShouldHandleAddress(name))
    {
        DebugPrint(L"Hooked connect to loopback! Setting send buffer to %d.", BUFFER_SIZE);
        int bufferSize = BUFFER_SIZE;
        int setsockoptError = setsockopt(
            s, 
            SOL_SOCKET, 
            SO_SNDBUF, 
            (char*)(&bufferSize), 
            sizeof(int));
        if (setsockoptError)
        {
            DebugPrint(L"Setting send buffer error %d", WSAGetLastError());
        }
    }
    else
    {
        DebugPrint(L"Hooked connect! Not loopack.");
    }
    
    int result = (*OriginalConnect)(s, name, namelen);
    return result;
}

int WSAAPI ListenHooked(
    SOCKET s,
    int backlog)
{
    DebugPrint(L"Hooked listen! Setting receive buffer to %d", BUFFER_SIZE);
    int bufferSize = BUFFER_SIZE;
    int setsockoptError = setsockopt(
        s, 
        SOL_SOCKET,
        SO_RCVBUF,
        (char*)(&bufferSize), 
        sizeof(int));
    if (setsockoptError)
    {
        DebugPrint(L"Setting receive buffer error %d", WSAGetLastError());
    }
    
    int result = (*OriginalListen)(s, backlog);
    return result;
}

BOOL CreateAndEnableHook(
    LPVOID targetFunc, 
    LPVOID replacementFunc, 
    LPVOID* originalFuncOutput, 
    const wchar_t* funcName)
{
    if (MH_CreateHook(targetFunc, replacementFunc, originalFuncOutput) != MH_OK)
    {
        DebugPrint(L"Failed to hook %s", funcName);
        return FALSE;
    }
    
    if (MH_EnableHook(targetFunc) != MH_OK)
    {
        DebugPrint(L"Failed to enable %s hook", funcName);
        return FALSE;
    }
    
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        if (MH_Initialize() != MH_OK)
        {
            DebugPrint(L"MinHook Init Failed!");
            return FALSE;
        }
        
        // Hook socket functions
        HMODULE hMod = LoadLibrary(L"ws2_32.dll");
        if (!hMod) {
            DebugPrint(L"LoadLibrary failed: %d", GetLastError());
            return FALSE;
        }
        
        // Replace the original functions with our hooked functions
        if (!CreateAndEnableHook(
            (LPVOID)&WSAConnect, 
            (LPVOID)&WSAConnectHooked, 
            reinterpret_cast<LPVOID*>(&OriginalWSAConnect),
            L"WSAConnect"))
        {
            return TRUE;
        }
        
        if (!CreateAndEnableHook(
            (LPVOID)&connect, 
            (LPVOID)&ConnectHooked, 
            reinterpret_cast<LPVOID*>(&OriginalConnect),
            L"connect"))
        {
            return TRUE;
        }
        
        if (!CreateAndEnableHook(
            (LPVOID)&listen, 
            (LPVOID)&ListenHooked, 
            reinterpret_cast<LPVOID*>(&OriginalListen),
            L"listen"))
        {
            return TRUE;
        }
        
        DebugPrint(L"Hooks installed!");
    }
    
    return TRUE;
}