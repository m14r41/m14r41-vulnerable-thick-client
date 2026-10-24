// VULN: #20 — CWE-121 — Stack buffer overflow
// Author: Madhurendra Kumar (M14R41) · © 2026
//
// Convert_LegacyText copies the caller-controlled narrow string into a fixed
// 128-byte stack buffer with strcpy. With /GS- /DYNAMICBASE:NO /NXCOMPAT:NO
// linked, overflowing the buffer overwrites the saved return address (or
// SEH chain on x64 with the right ancillary) and transfers control.
//
// SECURE FIX (writeup #20): bound by strncpy_s / StringCchCopyA, enable /GS,
// link with /DYNAMICBASE and /NXCOMPAT.

#include <windows.h>
#include <stdio.h>
#include <string.h>

extern "C" __declspec(dllexport)
int __cdecl Convert_LegacyText(const char* input, char* out, size_t out_bytes)
{
    char buf[128];
    // VULN: #20 — unbounded strcpy
    strcpy(buf, input);
    _snprintf(out, out_bytes, "converted:%s", buf);
    return (int)strlen(out);
}
