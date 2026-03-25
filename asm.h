#pragma once
#include <cstdint>

extern "C" {
    extern uintptr_t pebBase;
    void GetMyPeb();
}

namespace NTDLL {
    extern uintptr_t ldr;
    extern uintptr_t ntBase;
}