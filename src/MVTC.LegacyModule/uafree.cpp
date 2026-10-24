// VULN: #22 — CWE-416 — Use-after-free / double free
// Author: Madhurendra Kumar (M14R41) · © 2026
//
// OpenLegacyProject allocates a project blob. CloseLegacyProject frees it but
// does NOT null the pointer. OpenLegacyProject called again returns the same
// address — reclaimable by the attacker — and the next invocation of a
// method on the stale pointer calls into attacker-chosen memory.
//
// SECURE FIX (writeup #22): zero / null the pointer on free, prefer RAII
// (std::unique_ptr) + explicit ownership transfer, and build with
// AddressSanitizer in CI.

#include <windows.h>
#include <stdlib.h>
#include <string.h>

typedef struct Project
{
    void (*vtable_notify)(struct Project*);
    char name[64];
} Project;

static Project* g_project = nullptr;

static void default_notify(Project* p)
{
    (void)p;
}

extern "C" __declspec(dllexport)
Project* __cdecl OpenLegacyProject(const char* name)
{
    if (g_project == nullptr)
    {
        g_project = (Project*)malloc(sizeof(Project));
    }
    g_project->vtable_notify = default_notify;
    strncpy(g_project->name, name, sizeof(g_project->name) - 1);
    g_project->name[sizeof(g_project->name) - 1] = '\0';
    return g_project;
}

extern "C" __declspec(dllexport)
void __cdecl CloseLegacyProject(Project* p)
{
    // VULN: #22 — free without clearing g_project; next call reclaims the same
    // slab and a dangling pointer stays alive.
    free(p);
}

extern "C" __declspec(dllexport)
void __cdecl NotifyLegacyProject()
{
    if (g_project && g_project->vtable_notify)
        g_project->vtable_notify(g_project);
}
