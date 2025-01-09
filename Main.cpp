#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "ManualMapper.hpp"

#define LOG(text, ...) printf(text, __VA_ARGS__);

const DWORD getProcId(const char* procName) {
    const auto procHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    if (procHandle == INVALID_HANDLE_VALUE || !procHandle) {
        std::cerr << "Failed to create process snapshot.\n";
        return -1;  // Error handling
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(procHandle, &pe32)) {
        std::cerr << "Failed to retrieve the first process.\n";
        CloseHandle(procHandle);
        return -1;
    }

    do {
        if (!strcmp(pe32.szExeFile, procName)) { 
            CloseHandle(procHandle);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(procHandle, &pe32));

    CloseHandle(procHandle);
    return -1;  // Process not found
}


int main() {
	const char procName[] = "cs2.exe";
	const char dllPath[] = "C:\\Users\\user6900\\Desktop\\Simple-Manual-Map-Injector-master\\hello-world-x64.dll";

    const DWORD procId = getProcId(procName);

    LOG("Found Process with PID 0x%x\n", procId);


    // elevate our privilege,
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tokenPriv = { 0 };
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {   
        tokenPriv.PrivilegeCount = 1;
        tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPriv.Privileges[0].Luid))
            AdjustTokenPrivileges(token, FALSE, &tokenPriv, 0, NULL, NULL);

        CloseHandle(token);
    }

    const HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);

    if (hProc == INVALID_HANDLE_VALUE) {
        const auto err = GetLastError();
        LOG("Found Process with PID 0x%x\n", err);
    }

}
