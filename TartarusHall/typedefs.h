#pragma once
#include "Structs.h"

typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(
	DWORD				dwFlags,
	DWORD				th32ProcessID
);

typedef BOOL(WINAPI* fnThread32First)(
	HANDLE          hSnapshot,
	LPTHREADENTRY32 lpte
);

typedef BOOL(WINAPI* fnThread32Next)(
	HANDLE				hSnapshot,
	LPTHREADENTRY32		lpte
);

typedef NTSTATUS(NTAPI* fnLdrLoadDll)(
	PWCHAR             PathToFile,
	ULONG              Flags,
	PUNICODE_STRING    ModuleFileName,
	PHANDLE            ModuleHandle
);

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	USTRING* Data,   
	USTRING* Key     
);