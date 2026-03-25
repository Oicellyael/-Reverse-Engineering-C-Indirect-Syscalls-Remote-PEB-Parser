#include "asm.h"

extern "C" {
    uintptr_t pebBase = 0;
}

namespace NTDLL {
    uintptr_t ldr = 0;
    uintptr_t ntBase = 0;
}