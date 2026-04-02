#pragma comment(lib, "d3d11.lib")
#include <iostream>
#include <string>
#include <windows.h>
#include <chrono>
#include <cctype>
#include <ctype.h>
#include "asm.h"
#include <d3d11.h>
#include <tlhelp32.h>

using namespace std;

const BYTE expected[] = { 0x4C, 0x8B, 0xD1, 0xB8 };

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
    if (target == 0x5A4D) {
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

	uintptr_t pNtVirtualAllocEx = GetFunctionAddress(0xC86105CA);
	uintptr_t pNtVirtualFreeEx = GetFunctionAddress(0xB5567B67);
	uintptr_t NtProtectVirtualEx = GetFunctionAddress(0xA4D0D586);

    //uintptr_t realAddr2 = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    //uintptr_t realAddr3 = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
    //uintptr_t realAddr4 = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    //printf("My: NtAllocateVirtualMemory %p | Real: %p | Match: %s\n",
    //    (void*)pNtVirtualAllocEx,
    //    (void*)realAddr2,
    //    (pNtVirtualAllocEx == realAddr2) ? "YES" : "NO");
    //printf("My:NtFreeVirtualMemory %p | Real: %p | Match: %s\n",
    //    (void*)pNtVirtualFreeEx,
    //    (void*)realAddr3,
    //    (pNtVirtualFreeEx == realAddr3) ? "YES" : "NO");
    //printf("My:NtProtectVirtualMemory %p | Real: %p | Match: %s\n",
    //    (void*)NtProtectVirtualEx,
    //    (void*)realAddr4,
    //    (NtProtectVirtualEx == realAddr4) ? "YES" : "NO");
	
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
    cid.UniqueProcess = (HANDLE)(uintptr_t)targetPid;
    cid.UniqueThread = 0;

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
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
	g_ssn_allocate = GetSSN(pNtVirtualAllocEx, expected);
    g_ssn_free= GetSSN(pNtVirtualFreeEx, expected);
    g_ssn_protect= GetSSN(NtProtectVirtualEx, expected);

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
    }

   /* while (!GetAsyncKeyState(VK_DELETE)) {
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
    }*/
    return 0;
}
