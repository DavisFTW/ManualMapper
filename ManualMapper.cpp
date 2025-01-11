#include "ManualMapper.hpp"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)


void ManualMapper::debug() const {
	std::cerr << "ManualMapper Debug Information:\n";
	std::cerr << "--------------------------------\n";

	// Print handle and file size
	std::cerr << "Target Process Handle: " << handle_ << "\n";
	std::cerr << "Source Data Pointer: " << static_cast<void*>(srcData_) << "\n";
	std::cerr << "Source File Size: " << fileSize_ << " bytes\n";

	// Print NT Headers information
	if (pOldNtHeader) {
		std::cerr << "IMAGE_NT_HEADERS:\n";
		std::cerr << "  Signature: " << std::hex << pOldNtHeader->Signature << "\n";
	}
	else {
		std::cerr << "IMAGE_NT_HEADERS: Not Initialized\n";
	}

	// Print Optional Header information
	if (pOldOptHeader) {
		std::cerr << "IMAGE_OPTIONAL_HEADER:\n";
		std::cerr << "  ImageBase: " << std::hex << pOldOptHeader->ImageBase << "\n";
		std::cerr << "  SizeOfImage: " << pOldOptHeader->SizeOfImage << " bytes\n";
		std::cerr << "  AddressOfEntryPoint: " << std::hex << pOldOptHeader->AddressOfEntryPoint << "\n";
	}
	else {
		std::cerr << "IMAGE_OPTIONAL_HEADER: Not Initialized\n";
	}

	// Print File Header information
	if (pOldFileHeader) {
		std::cerr << "IMAGE_FILE_HEADER:\n";
		std::cerr << "  Machine: " << std::hex << pOldFileHeader->Machine << "\n";
		std::cerr << "  NumberOfSections: " << pOldFileHeader->NumberOfSections << "\n";
		std::cerr << "  Characteristics: " << std::hex << pOldFileHeader->Characteristics << "\n";
	}
	else {
		std::cerr << "IMAGE_FILE_HEADER: Not Initialized\n";
	}

	// Print target base allocation
	if (pTargetBase) {
		std::cerr << "Target Base Address: " << static_cast<void*>(pTargetBase) << "\n";
	}
	else {
		std::cerr << "Target Base Address: Not Allocated\n";
	}

	std::cerr << "--------------------------------\n";

	std::cerr << "Press Enter to continue...\n";
	std::cin.get();
}


bool ManualMapper::run() {
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(this->srcData_)->e_magic != 0x5A4D) { // signature
		std::cerr << "Invalid Header Signature\n";
		return false;
	}

	this->pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(this->srcData_ + reinterpret_cast<IMAGE_DOS_HEADER*>(this->srcData_)->e_lfanew);

	this->pOldOptHeader = &this->pOldNtHeader->OptionalHeader;
	this->pOldFileHeader = &this->pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		std::cerr << "Invalid arch\n";
	}

	this->pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(this->handle_, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {

		return false;
	}

	DWORD oldProtection = 0;
	VirtualProtectEx(this->handle_, this->pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtection);

	//  i need to make this more advanced as the dll that gets manual mapped inside the process wil still call LoadLibraryA and getProcAddress which can be monitored by any detection tool

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;

	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;

	data.pbase = pTargetBase;

	// write the PE HEADERS FIRST
	if (!memory::Write(this->handle_, this->pTargetBase, this->srcData_, 0x1000)) { // header is 0x1000 bytes large 
		std::cerr << "Failed to write PE HEADERS\n";
		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	// resolve all sections like .text .data .rdata 

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!memory::Write(this->handle_, this->pTargetBase + pSectionHeader->VirtualAddress,
				this->srcData_ + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData)) {
				std::cerr << "Error: Can't map sections. Error Code: " << GetLastError() << "\n";
				VirtualFreeEx(this->handle_, this->pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	// Allocating MANUAL MAPPING DATA 
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(this->handle_, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		std::cerr << "Error: Target process mapping allocation failed. Error Code: " << GetLastError() << "\n";
		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!memory::Write(this->handle_, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA))) {
		std::cerr << "Error: Can't write mapping data. Error Code: " << GetLastError() << "\n";
		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}
	return true;

	//Shell code
	void* pShellcode = VirtualAllocEx(this->handle_, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		std::cerr << "Error: Memory shellcode allocation failed. Error Code: " << GetLastError() << "\n";
		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(handle_, pShellcode, shellcode, 0x1000, nullptr)) {
		std::cerr << "Cant write shellcode\n";
		VirtualFreeEx(handle_, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(handle_, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(handle_, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	this->debug();

	HANDLE hThread = CreateRemoteThread(this->handle_, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		std::cerr << "thread Creation failed\n" << GetLastError();
		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	std::cout << "Thread created at " << pShellcode << " Waiting for shellcode to be executed" << std::endl;

	HINSTANCE hCheck = 0;

	while (!hCheck) {
		DWORD exitCode = 0;
		GetExitCodeProcess(this->handle_, &exitCode);

		if (exitCode != STILL_ACTIVE) {
			std::cerr << "Target Process Crashed" << exitCode;
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(this->handle_, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x0) {
			VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(this->handle_, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(this->handle_, pShellcode, 0, MEM_RELEASE);
			return false;
		}

		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, pShellcode, 0, MEM_RELEASE);

		//pause
		std::cerr << "Manual Mapping finished Press Enter to continue...\n";
		std::cin.get();

		return true;

	}
}
void __stdcall shellcode(MANUAL_MAPPING_DATA* mData) {

	// fix relocatios if needed ( base - preffered ) 

	if (!mData) {
		mData->hMod = reinterpret_cast<HINSTANCE>(0x0);  // best error handling
		std::cerr << "mData was invalid!\n";
		return;
	}

	BYTE* pBase = mData->pbase;

	const auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;


	const auto _LoadLibraryA = mData->pLoadLibraryA;
	const auto _GetProcAddress = mData->pGetProcAddress;

	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	auto _RtlAddFunctionTable = mData->pRtlAddFunctionTable;

	const BYTE* locationDelta = pBase - pOpt->ImageBase; // if we actually manage to set our dll inside a preffered image base no reloactions are needed


	// align mapped  dll if needed 
	if (locationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {   // if its valid
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			// everything is valid, parse it
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);  // pRelocData should point to IMAGE_BASE_RELOCATION adding + 1 makes it point to the next first relocation entry in the current block 1 = 8 bytes

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG64(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(locationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);  // move further
			}
		}
	}

	// get import descriptor
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescriptor->Name) {

			// dll is valid, load the sucker
			const char* moduleName = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
			HINSTANCE hDll = _LoadLibraryA(moduleName);
			ULONG_PTR* pOrigThunk = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFunc = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

			if (!pOrigThunk) { // sometimes they can be the same and IAT contains both
				pOrigThunk = pFunc;
			}

			// parse all data ILT IAT correspondingly 

			for (; *pOrigThunk; ++pOrigThunk, ++pFunc) { // both need to be upped so we can have the equal things
				if (IMAGE_SNAP_BY_ORDINAL(*pOrigThunk)) { // if the import is by number
					*pFunc = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<char*>(*pOrigThunk & 0xFFF))); // this might cause issues or not
				}
				else { // by name
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pOrigThunk));
					*pOrigThunk = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}

			}
			++pImportDescriptor;
		}
	}

	// FIX TLS 

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	mData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
