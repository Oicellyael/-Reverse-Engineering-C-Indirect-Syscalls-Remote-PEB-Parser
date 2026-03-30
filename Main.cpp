#pragma comment(lib, "d3d11.lib")
#include <iostream>
#include <string>
#include <windows.h>
#include <chrono>
#include < cctype >
#include <ctype.h>
#include "asm.h"
#include <d3d11.h>
#include <tlhelp32.h>

using namespace std;

const BYTE expected[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
uintptr_t g_ntOpen = 0;

extern "C" DWORD g_ssn = 0;
extern "C" DWORD g_ssn_read = 0;
extern "C" DWORD g_ssn_write = 0;
extern "C" uintptr_t g_syscallAddr = 0;
extern "C" DWORD g_ssn_thread = 0;
extern "C" DWORD g_ssn_QSI = 0;
extern "C" DWORD g_ssn_QIP = 0;


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

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
	PVOID PebBaseAddress; // Адрес PEB процесса
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

extern "C" NTSTATUS Syscall_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

extern "C" NTSTATUS Syscall_NtReadVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead
);

extern "C" NTSTATUS Syscall_NtWriteVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      BufferSize,
    PSIZE_T     NumberOfBytesWritten
);

extern "C" NTSTATUS Syscall_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

extern "C" NTSTATUS Syscall_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

extern "C" NTSTATUS Syscall_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass, 
    PVOID ProcessInformation,      
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // 0x00
    LIST_ENTRY InMemoryOrderLinks;         // 0x10
    LIST_ENTRY InInitializationOrderLinks;   // 0x20
	PVOID DllBase;                         // 0x30 <- need this
    PVOID EntryPoint;                      // 0x38
    ULONG SizeOfImage;                     // 0x40
    UNICODE_STRING FullDllName;            // 0x48
	UNICODE_STRING BaseDllName;     // 0x58 <- need this
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

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

template <typename T>
T Read(HANDLE hProc, uintptr_t address) {
    T buffer;
    Syscall_NtReadVirtualMemory(hProc, (PVOID)address, &buffer, sizeof(T), NULL); //Read<uintptr_t>(hProcess, clientBase + offsets);
    return buffer;
}
template <typename T>
bool Write(HANDLE hProc, uintptr_t address, T value) {
    NTSTATUS status = Syscall_NtWriteVirtualMemory(hProc,(PVOID)address,&value,sizeof(T),NULL); //Write<bool>(hProcess, targetAddress(client+offsets), our bool) 
    return (status == 0);
}


INPUT clicks[2] = {};

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
    uintptr_t pNtCreateThreadEx = GetFunctionAddress(0xFE3E696E);
    uintptr_t pNtQueryInformationProcess = GetFunctionAddress(0xA405E60);

    f_NtOpenProcess _NtOpenProcess;
    f_NtReadVirtualMemory _NtReadVirtualMemory;
    f_NtWriteVirtualMemory _NtWriteVirtualMemory;
    f_NtQuerySystemInformation _NtQuerySystemInformation;
    _NtOpenProcess = (f_NtOpenProcess)ntOpen;
    _NtReadVirtualMemory = (f_NtReadVirtualMemory)pNtRead;
    _NtWriteVirtualMemory = (f_NtWriteVirtualMemory)pNtWrite;
    _NtQuerySystemInformation = (f_NtQuerySystemInformation)pNtSysInfo;

    ULONG bufferSize = 0;
    _NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    void* buffer = malloc(size_t(bufferSize));
    _NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
    DWORD targetPid = 0;

    while (true) {
        if (pCurrent->ImageName.Buffer != NULL) {
            if (_wcsicmp(pCurrent->ImageName.Buffer, L"cs2.exe") == 0) {
                targetPid = (DWORD)pCurrent->UniqueProcessId;
                break;
            }
        }
        if (pCurrent->NextEntryOffset == 0)
            break;
        pCurrent = (PSYSTEM_PROCESS_INFORMATION)((uintptr_t)pCurrent + pCurrent->NextEntryOffset);
    }
    free(buffer);

    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(uintptr_t)targetPid; // Превращаем число с dword into 8 byte
    cid.UniqueThread = 0;

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(OBJECT_ATTRIBUTES); // need for NtOpenprocess
    oa.RootDirectory = NULL;
    oa.Attributes = 0;
    oa.ObjectName = NULL;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    g_ntOpen = ntOpen;
    g_ssn = GetSSN(ntOpen, expected);
    g_ssn_read = GetSSN(pNtRead, expected);
    g_ssn_write = GetSSN(pNtWrite, expected);
    g_ssn_QSI = GetSSN(pNtSysInfo, expected);
    g_ssn_thread = GetSSN(pNtCreateThreadEx, expected);
    g_ssn_QIP = GetSSN(pNtQueryInformationProcess, expected);

    DWORD dwDesiredAccess = 0x0438;
    HANDLE hProcess = 0;
    NTSTATUS status = Syscall_NtOpenProcess(&hProcess, dwDesiredAccess, &oa, &cid);

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS qipStatus = Syscall_NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
    uintptr_t remoteLdr = 0;
    NTSTATUS readStatus = Syscall_NtReadVirtualMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x18), &remoteLdr, sizeof(remoteLdr), NULL);
    if (readStatus == 0) {
        printf("Ldr found at: %p\n", (void*)remoteLdr);
    }

    uintptr_t listHeadAddr = remoteLdr + 0x10;
    uintptr_t currentEntry = 0;
    readStatus = Syscall_NtReadVirtualMemory(hProcess, (PVOID)listHeadAddr, &currentEntry, sizeof(currentEntry), NULL);
    uintptr_t clientBase = 0;

    while (currentEntry != listHeadAddr) {
        LDR_DATA_TABLE_ENTRY entry;
        readStatus = Syscall_NtReadVirtualMemory(hProcess, (PVOID)currentEntry, &entry, sizeof(entry), NULL);
        if (readStatus == 0) {
            wchar_t* dllName = (wchar_t*)malloc(entry.BaseDllName.Length + sizeof(wchar_t));
            if (dllName) {
                readStatus = Syscall_NtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, dllName, entry.BaseDllName.Length, NULL);
                if (readStatus == 0) {
                    dllName[entry.BaseDllName.Length / sizeof(wchar_t)] = L'\0';
                    if (_wcsicmp(L"client.dll", dllName) == 0) {
                        clientBase = (uintptr_t)entry.DllBase;
                        printf("DOMINATION! client.dll found at: %p\n", entry.DllBase);
                        free(dllName);
                        break;
                    }
                }
                free(dllName);
            }
        }
        currentEntry = (uintptr_t)entry.InLoadOrderLinks.Flink;
        if (currentEntry == 0) break;
    }
    //Read<uintptr_t>(hProcess, clientBase + offsets);
    //Write<bool>(hProcess, targetAddress(client+offsets), our bool) 
    while (!GetAsyncKeyState(VK_DELETE)) {

        if (clientBase != 0) {
            uintptr_t localController = Read<uintptr_t>(hProcess, clientBase + 0x22F5028);
            uintptr_t localPawn = Read<uintptr_t>(hProcess, clientBase + 0x206A9E0);

            if (localController != 0 && localPawn != 0) {
                int localHp = Read<int>(hProcess, localPawn + 0x354);
                
                system("cls");
                printf("================================================================\n");
                printf("        INDIRECT SYSCALLS ENGINE v1.0 - CS2 EXPLORATION         \n");
                printf("================================================================\n");

                printf("[*] LOCAL ENVIRONMENT:\n");
                printf("    |-> PEB Address:       0x%p\n", (void*)pebBase);
                printf("    |-> NTDLL Base:        0x%p\n", (void*)NTDLL::ntBase);
                printf("    |-> Syscall Jump Addr: 0x%p\n", (void*)g_syscallAddr);

                printf("\n[*] SYSTEM SERVICE NUMBERS (SSN) FOUND:\n");
                printf("    |-> NtOpenProcess:     [0x%04X]\n", g_ssn);
                printf("    |-> NtReadVirtualMem:  [0x%04X]\n", g_ssn_read);
                printf("    |-> NtWriteVirtualMem: [0x%04X]\n", g_ssn_write);
                printf("    |-> NtQuerySystemInfo: [0x%04X]\n", g_ssn_QSI);
                printf("    |-> NtQueryInfoProc:   [0x%04X]\n", g_ssn_QIP);

                printf("\n[*] TARGET PROCESS (PID: %d):\n", targetPid);
                printf("    |-> Access Mask:       0x%04X (STEALTH)\n", dwDesiredAccess);
                printf("    |-> Remote PEB:        0x%p\n", pbi.PebBaseAddress);
                printf("    |-> Remote LDR:        0x%p\n", (void*)remoteLdr);

                printf("\n[*] MODULE MAPPING:\n");
                printf("    |-> Found Module:      [client.dll]\n");
                printf("    |-> Base Address:      0x%p\n", (void*)clientBase);

                printf("\n[+] LIVE GAME DATA:\n");
                printf("    |- LocalController:    0x%p\n", (void*)localController);
                printf("    |- LocalPawn:          0x%p\n", (void*)localPawn);
                printf("    |- Current HP:         %d\n", localHp);
            }
        }
    }
    return 0;
}
