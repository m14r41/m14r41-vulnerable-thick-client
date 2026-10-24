// MVTC.Helper.Native (AppHelper.dll)
// Benign helper DLL. The vulnerability is NOT in this file; it is in the
// MVTC.App code that loads this DLL by bare name (see
// MVTC.Core/Services/Vuln/DllHelperLoader.cs — VULN #1 / #7).
//
// Created by Madhurendra Kumar (M14R41) · © 2026 · M14R41 Labs

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int AppHelper_Init()      { return 0; }
extern "C" __declspec(dllexport) int AppHelper_Transform() { return 0; }
