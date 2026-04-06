#include "asm.h"
#include <cstring>

extern "C" {
    uintptr_t pebBase = 0;
    DWORD g_ssn = 0;
    DWORD g_ssn_read = 0;
    DWORD g_ssn_write = 0;
    uintptr_t g_syscallAddr = 0;
    DWORD g_ssn_thread = 0;
    DWORD g_ssn_QSI = 0;
    DWORD g_ssn_QIP = 0;
    uintptr_t g_ntOpen = 0;
    DWORD g_ssn_allocate = 0;
    DWORD g_ssn_free = 0;
    DWORD g_ssn_protect=0;
   DWORD g_ssn_duplicate = 0;
}

namespace NTDLL {
    uintptr_t ldr = 0;
    uintptr_t ntBase = 0;
}

DWORD MyHasher(const char* word) {
    DWORD hash = 4291;
    int c;
    while ((c = *word++)) {
        if (isupper(c)) {
            c = c + 32;
        }
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

uintptr_t GetFunctionAddress(DWORD targetHash) {
    DWORD PeStart = *(DWORD*)(NTDLL::ntBase + 0x3C);
    DWORD exportRVA = *(DWORD*)(NTDLL::ntBase + PeStart + 0x88);
    uintptr_t EDAddress = NTDLL::ntBase + exportRVA;
    DWORD numNames = *(DWORD*)(EDAddress + 0x18);
    uintptr_t functionAddress = 0;
    uintptr_t namesAddr = NTDLL::ntBase + *(DWORD*)(EDAddress + 0x20);
    uintptr_t ordinalsAddr = NTDLL::ntBase + *(DWORD*)(EDAddress + 0x24);
    uintptr_t functionsAddr = NTDLL::ntBase + *(DWORD*)(EDAddress + 0x1C);
    DWORD nameRVA = 0;
    for (DWORD i = 0; i < numNames; i++) {
        DWORD name = *(DWORD*)(namesAddr + i * 4);
        char* namestr = (char*)(NTDLL::ntBase + name);
        DWORD target = MyHasher(namestr);
        if (target == targetHash) {
            WORD ordinal = *(WORD*)(ordinalsAddr + i * 2);
            DWORD functionRVA = *(DWORD*)(functionsAddr + (ordinal * 4));
            functionAddress = NTDLL::ntBase + functionRVA;
            break;
        }
    }
    return functionAddress;
}

DWORD GetSSN(uintptr_t address, const BYTE* pattern) {
    BYTE* mem = (BYTE*)address;
    if (memcmp(mem, pattern, 4) == 0) {
        for (size_t i = 0; i < 32; i++) {
            if (mem[i] == 0x0F && mem[i + 1] == 0x05) {
                g_syscallAddr = address + i;
                break;
            }
        }
        return *(DWORD*)(address + 4);
    }
    return 0;
}
