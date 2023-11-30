#pragma once
#include <Windows.h>

// uncomment to enable debug mode
//\
#define DEBUG

#ifdef DEBUG

HANDLE   GetConsoleHandle();

#define PRINTW( STR, ... )                                                                      \
    if (1) {                                                                                    \
        HANDLE hConsole = NULL;                                                                 \
        if ((hConsole = GetConsoleHandle()) == NULL){}                                          \
        else{                                                                                   \
            LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
            if ( buf != NULL ) {                                                                \
                INT len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
                WriteConsoleW( hConsole, buf, len, NULL, NULL );			                    \
                HeapFree( GetProcessHeap(), 0, buf );                                           \
            }                                                                                   \
        }                                                                                       \
    }

#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            INT len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  
#endif // DEBUG