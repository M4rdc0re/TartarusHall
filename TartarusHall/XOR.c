#include <Windows.h>

VOID XOR(PBYTE Dst, PBYTE Src, SIZE_T Size) {

	for (int i = 0; i < Size; i++) {
		if (i % 2 == 0)
			Dst[i] = Src[i] ^ (0xFB + i);
		else
			Dst[i] = Src[i] ^ (0xA1 + (i - 1));
	}
}