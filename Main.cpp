#pragma comment(lib, "d3d11.lib")
#include <iostream>
#include <string>
#include <chrono>
#include < cctype >
#include <ctype.h>
#include "asm.h"
#include <d3d11.h>
#include <tlhelp32.h>

using namespace std;

typedef LONG NTSTATUS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* f_NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* f_NtReadVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* f_NtWriteVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesWritten
    );

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* f_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;     
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;    
    LONG BasePriority;
    HANDLE UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

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
    uintptr_t pNtSysInfo = GetFunctionAddress(0x684921E6);

    f_NtOpenProcess _NtOpenProcess;
    f_NtReadVirtualMemory _NtReadVirtualMemory;
    f_NtWriteVirtualMemory _NtWriteVirtualMemory;
    _NtOpenProcess = (f_NtOpenProcess)ntOpen;
    _NtReadVirtualMemory = (f_NtReadVirtualMemory)pNtRead;
    _NtWriteVirtualMemory = (f_NtWriteVirtualMemory)pNtWrite;

    void* buffer = malloc(size_t(buffer));
    PSYSTEM_PROCESS_INFORMATION pСurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
    DWORD targetPid = 0;

    do {
        pСurrent = (PSYSTEM_PROCESS_INFORMATION)((uintptr_t)pСurrent + pСurrent->NextEntryOffset);
        if (pСurrent->ImageName.Buffer != NULL) {
            if (_wcsicmp(pСurrent->ImageName.Buffer, L"cs2.exe") == 0) {
                targetPid = (DWORD)pСurrent->UniqueProcessId;
                break;
            }

        }
    } while (pСurrent->NextEntryOffset);
    free(buffer);
    while (!GetAsyncKeyState(VK_DELETE)) {}
    return 0;  
}
