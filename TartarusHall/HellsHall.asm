.data
	wSystemCall         DWORD	0h
	qSyscallInsAdress   QWORD	0h


.code

	SetSSn proc
		xor eax, eax                          ; eax = 0
		nop									  ; obfuscation
		mov wSystemCall, eax                  ; wSystemCall = 0
		nop									  ; obfuscation
		mov qSyscallInsAdress, rax            ; qSyscallInsAdress = 0
		nop									  ; obfuscation
		mov eax, ecx                          ; eax = ssn
		nop									  ; obfuscation
		mov wSystemCall, eax                  ; wSystemCall = eax = ssn
		nop									  ; obfuscation
		mov r8, rdx                           ; r8 = AddressOfASyscallInst
		nop									  ; obfuscation
		mov qSyscallInsAdress, r8             ; qSyscallInsAdress = r8 = AddressOfASyscallInst
		ret
	SetSSn endp


	RunSyscall proc
		xor r10, r10                          ; r10 = 0
		nop									  ; obfuscation
		mov rax, rcx                          ; rax = rcx
		nop									  ; obfuscation
		mov r10, rax                          ; r10 = rax = rcx
		nop									  ; obfuscation
		mov eax, wSystemCall                  ; eax = ssn
		nop									  ; obfuscation
		jmp Run                               ; execute 'Run'
		xor eax, eax						  ; obfuscation
		xor rcx, rcx						  ; obfuscation
		shl r10, 2							  ; obfuscation
	Run:
		jmp qword ptr [qSyscallInsAdress]     ; jumping to the 'syscall' instruction
		nop									  ; ofuscation
		xor r10, r10                          ; r10 = 0
		nop									  ; ofuscation
		mov qSyscallInsAdress, r10            ; qSyscallInsAdress = 0
		ret
	RunSyscall endp

end