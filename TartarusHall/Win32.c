#include <Windows.h>
#include "Common.h"

UINT32 _crc32h(PCHAR message) {
    INT32 i, crc;
    UINT32 byte, c;
    CONST UINT32 g0 = SEED, g1 = g0 >> 1,
        g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
        g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

    i = 0;
    crc = 0xFFFFFFFF;
    while ((byte = message[i]) != 0) {    // Get next byte.
        crc = crc ^ byte;
        c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
            ((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
            ((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
            ((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
        crc = ((UINT32)crc >> 8) ^ c;
        i = i + 1;
    }
    return ~crc;
}

SIZE_T _CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0) {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SIZE_T _StrlenA(LPCSTR String)
{

    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T _StrlenW(LPCWSTR String)
{

    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

UINT32 _CopyDotStr(PCHAR String)
{
    for (UINT32 i = 0; i < _StrlenA(String); i++)
    {
        if (String[i] == '.')
            return i;
    }
}

VOID _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    if ((target->Buffer = (PWSTR)source))
    {
        UINT32 length = wcslen(source) * sizeof(WCHAR);
        if (length > 0xfffc)
            length = 0xfffc;

        target->Length = length;
        target->MaximumLength = target->Length + sizeof(WCHAR);
    }
    else target->Length = target->MaximumLength = 0;
}

PVOID _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

WCHAR* _strcpy(WCHAR* dest, CONST WCHAR* src)
{
    WCHAR* p;

    if ((dest == NULL) || (src == NULL))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}

WCHAR* _strcat(WCHAR* dest, CONST WCHAR* src)
{
    if ((dest == NULL) || (src == NULL))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}