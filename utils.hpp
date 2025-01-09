#ifndef UTILS_HPP
#define UTILS_HPP

#include <windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <optional>
#include <string>

namespace Utils {
    constexpr DWORD INVALID_HANDLE_ID = static_cast<DWORD>(-1);
    constexpr DWORD INVALID_PROCESS_ID = static_cast<DWORD>(-2);
    constexpr DWORD PROCESS_NOT_FOUND = static_cast<DWORD>(-3);

    const DWORD getProcId(const char* procName);
    bool LoadDllFile(const char* dllPath, BYTE*& pSrcData, SIZE_T& fileSize, HANDLE procHandle);
    bool ElevatePrivilege(const char* privilegeName);
}

#endif // UTILS_HPP
