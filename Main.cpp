#pragma comment(lib, "d3d11.lib")
#include "help/help.h"
#include <iostream>
#include <mutex>
#include <string>
#include <chrono>
#include < winternl.h >
#include < cctype >
#include <ctype.h>
#include "asm.h"

using namespace std;

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
	DWORD PeStart = *(DWORD*)(NTDLL::ntBase + 0x3C);// Получаем смещение к PE заголовку
	DWORD exportRVA = *(DWORD*)(NTDLL::ntBase + PeStart + 0x88);// Получаем RVA к экспортной таблице РВА (Relative Virtual Address) - это смещение от базового адреса модуля до определенного элемента, такого как функция или переменная.    
	uintptr_t EDAddress = NTDLL::ntBase + exportRVA; // Получаем адрес экспортной таблицы
	DWORD numNames = *(DWORD*)(EDAddress + 0x18);// Получаем количество имен экспортируемых функций
	uintptr_t functionAddress = 0;// Адрес искомой функции
	uintptr_t namesAddr = NTDLL::ntBase + *(DWORD*)(EDAddress + 0x20);// Получаем адрес массива имен экспортируемых функций
	uintptr_t ordinalsAddr = NTDLL::ntBase + *(DWORD*)(EDAddress + 0x24);// Получаем адрес массива порядковых номеров экспортируемых функций
	uintptr_t functionsAddr = NTDLL::ntBase + *(DWORD*)(EDAddress + 0x1C);// Получаем адрес массива адресов экспортируемых функций
	DWORD nameRVA = 0;// RVA к имени функции
    for (DWORD i = 0; i < numNames; i++) {
        DWORD name =*(DWORD*)(namesAddr + i * 4); // 
       char* namestr= (char*)(NTDLL::ntBase + name);
      DWORD target= MyHasher(namestr);
        if (target == targetHash) {
			WORD ordinal = *(WORD*)(ordinalsAddr + i * 2);// Получаем порядковый номер функции
			DWORD functionRVA =*(DWORD*)( functionsAddr+ (ordinal*4));// Получаем порядковый номер функции, добавив базовый порядковый номер
			functionAddress = NTDLL::ntBase + functionRVA;// Получаем адрес функции, добавив базовый адрес модуля
            break;
        }
    }
	return functionAddress;
}

int main() {

    GetMyPeb();

    if (pebBase == 0) {
        printf("Ошибка: Не удалось получить PEB!\n");
        return 1;
    }
    NTDLL::ldr = *(uintptr_t*)(pebBase + 0x18);
    uintptr_t anchor = (NTDLL::ldr + 0x10);
    uintptr_t current = *(uintptr_t*)anchor;
    do {
        uintptr_t bufferAddress = *(uintptr_t*)(current + 0x60);
        if (bufferAddress != 0) {
            wchar_t* dllName = (wchar_t*)bufferAddress;
            if (_wcsicmp(dllName, L"ntdll.dll") == 0) {
                NTDLL::ntBase = *(uintptr_t*)(current + 0x30);
                break;
            }
        }
        current = *(uintptr_t*)current;
    } while (current != anchor);
    if (NTDLL::ntBase != 0) {
        printf("NTDLL Found at: %p\n", (void*)NTDLL::ntBase);
    }
    else {
        printf("NTDLL not found!\n");
    }
    unsigned short target = *(unsigned short*)NTDLL::ntBase;
    if (target == 0x5A4D) { // 'M' и 'Z'
        printf("Signature confirmed: MZ is here!\n");
    }
    else {
        printf("????\n");
    }
    uintptr_t ntOpen = GetFunctionAddress(0x3F4DD136);
    uintptr_t pNtRead = GetFunctionAddress(0x307C3661);
    uintptr_t pNtWrite = GetFunctionAddress(0xFAE162D0);
    //uintptr_t realAddr = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    //uintptr_t realAddr2 = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    //uintptr_t realAddr3 = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    //Hash NtReadVirtualMemory is : 0x307C3661
    //Hash NtWriteVirtualMemory is : 0xFAE162D0


    // Теперь передаем все 3 значения для 3-х спецификаторов (%p, %p, %s)
    /*printf("My: NtOpenProcess %p | Real: %p | Match: %s\n",
        (void*)myAddr,
        (void*)realAddr,
        (myAddr == realAddr) ? "YES" : "NO");
    printf("My:NtReadVirtualMemory %p | Real: %p | Match: %s\n",
        (void*)pNtRead,
        (void*)realAddr2,
        (pNtRead == realAddr2) ? "YES" : "NO");
    printf("My:NtWriteVirtualMemory %p | Real: %p | Match: %s\n",
        (void*)pNtWrite,
        (void*)realAddr3,
        (pNtWrite == realAddr3) ? "YES" : "NO");*/
    while (!GetAsyncKeyState(VK_DELETE)) {
    }
    return 0;
    
}