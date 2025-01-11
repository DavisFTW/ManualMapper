#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>


// yes i did not invent this but why should i ? 
using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);


struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;  // pointer to base address where dll is loaded
	HINSTANCE hMod; // handle to loaded dll
	DWORD fdwReasonParam; // param for dll
	LPVOID reservedParam; // param for dll
	//BOOL SEHSupport; // SEH doesnt work so implement this ? 
};

class ManualMapper
{
private:

	//passed from constructor caller
	// handle_ handle to target process
	// srcData_ 
	HANDLE handle_;
	BYTE* srcData_;
	std::streampos fileSize_;

	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;
	void __stdcall shellcode(MANUAL_MAPPING_DATA* mData);

public:
	ManualMapper(const HANDLE handle, BYTE* srcData, std::streampos fileSize)
		: handle_(handle), srcData_(srcData), fileSize_(fileSize) {}

	bool run();
};

namespace memory{
	template<typename T>
	bool Write(HANDLE hProc, LPVOID targetAddress, const T* buffer, SIZE_T size) {
		SIZE_T bytesWritten = 0;
		if (!WriteProcessMemory(hProc, targetAddress, buffer, size, &bytesWritten)) {
			DWORD err = GetLastError();
			std::cerr << "Error: WriteProcessMemory failed. Address: "
				<< targetAddress << ", Size: " << size
				<< ", Error Code: " << err << "\n";
			return false;
		}
		if (bytesWritten != size) {
			std::cerr << "Error: WriteProcessMemory wrote incomplete data. Expected: "
				<< size << ", Written: " << bytesWritten << "\n";
			return false;
		}
		return true;


	}

	template<typename T>
	bool Read(HANDLE hProc, LPCVOID targetAddress, T* buffer, SIZE_T size) {
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProc, targetAddress, buffer, size, &bytesRead)) {
			DWORD err = GetLastError();
			std::cerr << "Error: ReadProcessMemory failed. Address: "
				<< targetAddress << ", Size: " << size
				<< ", Error Code: " << err << "\n";
			return false;
		}
		if (bytesRead != size) {
			std::cerr << "Error: ReadProcessMemory read incomplete data. Expected: "
				<< size << ", Read: " << bytesRead << "\n";
			return false;
		}
		return true;
	}
}
