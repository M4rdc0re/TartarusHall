#pragma once
#include "Structs.h"

typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(
	IN DWORD				dwFlags,
	IN DWORD				th32ProcessID
);

typedef BOOL(WINAPI* fnThread32First)(
	IN		HANDLE          hSnapshot,
	IN OUT	LPTHREADENTRY32 lpte
);

typedef BOOL(WINAPI* fnThread32Next)(
	IN  HANDLE				hSnapshot,
	OUT LPTHREADENTRY32		lpte
);

typedef BOOL(WINAPI* fnCloseHandle)(
	IN HANDLE				hObject
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