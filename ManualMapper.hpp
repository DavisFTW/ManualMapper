#pragma once
#include <windows.h>
#include <fstream>
class ManualMapper
{
private:

	//passed from constructor caller
	HANDLE handle_;
	const BYTE* srcData_;
	std::streampos fileSize_;

	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

public:
	ManualMapper(const HANDLE handle, const BYTE* srcData, std::streampos fileSize)
		: handle_(handle), srcData_(srcData), fileSize_(fileSize) {}

	bool run();
};

