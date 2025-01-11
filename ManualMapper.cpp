#include "ManualMapper.hpp"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

void __stdcall ManualMapper::shellcode(MANUAL_MAPPING_DATA* mData)
{

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

	// load dll

	// Get the first Original Thunk and The firstThunk verify them

	// use ILT to get the ordinal or name

	// use IAT to fix the corresponding imports address by using _getProcAddress


}

bool ManualMapper::run()
{
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(this->srcData_)->e_magic != 0x5A4D){ // signature
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

	if (!memory::Write(this->handle_, pShellcode, Shellcode, 0x1000)) {
		std::cerr << "Error: Can't write shellcode. Error Code: " << GetLastError() << "\n";
		VirtualFreeEx(this->handle_, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle_, pShellcode, 0, MEM_RELEASE);
		return false;
	}
}
