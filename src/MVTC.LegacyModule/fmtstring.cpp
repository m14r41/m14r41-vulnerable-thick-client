// VULN: #21 — CWE-134 — Format-string vulnerability
// Author: Madhurendra Kumar (M14R41) · © 2026
//
// LegacyLog passes the caller-controlled narrow string DIRECTLY as the format
// argument to printf. `%s`, `%x`, `%n`, `%p` all become attacker-controlled
// side-effects — read-arbitrary with %s/%x and write-arbitrary with %n.
//
// SECURE FIX (writeup #21): always route caller text through a fixed format
// string: printf("%s", input).

#include <windows.h>
#include <stdio.h>

extern "C" __declspec(dllexport)
void __cdecl LegacyLog(const char* userInput)
{
    // VULN: #21 — attacker-controlled format string
    printf(userInput);
}
