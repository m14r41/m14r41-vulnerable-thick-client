// VULN: #23 — CWE-190 — Integer overflow leading to undersized heap allocation
// Author: Madhurendra Kumar (M14R41) · © 2026
//
// AllocLegacyPages multiplies a caller-controlled 32-bit count by sizeof(Page)
// (64 bytes). With count ≈ 0x4000_0000+ the multiplication wraps around to a
// small size; the subsequent write-loop walks far past the allocation.
//
// SECURE FIX (writeup #23): either (a) check for overflow before multiplying
//   if (count > SIZE_MAX / sizeof(Page)) return E_OVERFLOW;
// or (b) use calloc which performs the check for you.

#include <windows.h>
#include <stdlib.h>

typedef struct Page { char data[64]; } Page;

extern "C" __declspec(dllexport)
Page* __cdecl AllocLegacyPages(unsigned int count)
{
    // VULN: #23 — integer overflow on count * sizeof(Page) when count is large.
    size_t bytes = (size_t)(count * sizeof(Page));
    Page* pages = (Page*)malloc(bytes);
    if (!pages) return nullptr;
    for (unsigned int i = 0; i < count; i++)
    {
        memset(&pages[i], 0xAA, sizeof(Page));
    }
    return pages;
}
