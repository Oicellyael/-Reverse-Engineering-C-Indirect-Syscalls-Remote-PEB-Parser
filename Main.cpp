#pragma comment(lib, "d3d11.lib")
#include "help/help.h"
#include <windows.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>

#include "asm.h"

namespace {

    constexpr BYTE kZwFunctionStub[] = { 0x4C, 0x8B, 0xD1, 0xB8 }; // mov r10, rcx ; mov eax, SSN

    // FNV-like export hashes (unchanged)
    constexpr DWORD kNtOpenProcess = 0x3F4DD136;
    constexpr DWORD kNtReadVirtualMemory = 0x307C3661;
    constexpr DWORD kNtWriteVirtualMemory = 0xFAE162D0;
    constexpr DWORD kNtQuerySystemInformation = 0x684921E6;
    constexpr DWORD kNtCreateThreadEx = 0xFE3E696E;
    constexpr DWORD kNtQueryInformationProcess = 0x0A405E60;
    constexpr DWORD kNtAllocateVirtualMemory = 0xC86105CA;
    constexpr DWORD kNtFreeVirtualMemory = 0xB5567B67;
    constexpr DWORD kNtProtectVirtualMemory = 0xA4D0D586;
    constexpr DWORD kNtDuplicateObject = 0x781AA9F7;

    constexpr ACCESS_MASK kOpenProcessDesiredAccess = 0x0438;
    constexpr ACCESS_MASK kDuplicateSameAccess = 0x2;
    constexpr ACCESS_MASK kProcessFullControl = 0x1FFFFF;

    constexpr NTSTATUS kNtStatusBufferTooSmall = 0xC0000004L;

    struct NtRoutines {
        uintptr_t ntOpenProcess = 0;
        uintptr_t ntReadVirtualMemory = 0;
        uintptr_t ntWriteVirtualMemory = 0;
        uintptr_t ntQuerySystemInformation = 0;
        uintptr_t ntCreateThreadEx = 0;
        uintptr_t ntQueryInformationProcess = 0;
        uintptr_t ntAllocateVirtualMemory = 0;
        uintptr_t ntFreeVirtualMemory = 0;
        uintptr_t ntProtectVirtualMemory = 0;
        uintptr_t ntDuplicateObject = 0;
    };

    bool ResolveNtRoutines(NtRoutines& out) {
        out.ntOpenProcess = GetFunctionAddress(kNtOpenProcess);
        out.ntReadVirtualMemory = GetFunctionAddress(kNtReadVirtualMemory);
        out.ntWriteVirtualMemory = GetFunctionAddress(kNtWriteVirtualMemory);
        out.ntQuerySystemInformation = GetFunctionAddress(kNtQuerySystemInformation);
        out.ntCreateThreadEx = GetFunctionAddress(kNtCreateThreadEx);
        out.ntQueryInformationProcess = GetFunctionAddress(kNtQueryInformationProcess);
        out.ntAllocateVirtualMemory = GetFunctionAddress(kNtAllocateVirtualMemory);
        out.ntFreeVirtualMemory = GetFunctionAddress(kNtFreeVirtualMemory);
        out.ntProtectVirtualMemory = GetFunctionAddress(kNtProtectVirtualMemory);
        out.ntDuplicateObject = GetFunctionAddress(kNtDuplicateObject);

        return out.ntOpenProcess != 0 &&
            out.ntReadVirtualMemory != 0 &&
            out.ntWriteVirtualMemory != 0 &&
            out.ntQuerySystemInformation != 0 &&
            out.ntCreateThreadEx != 0 &&
            out.ntQueryInformationProcess != 0 &&
            out.ntAllocateVirtualMemory != 0 &&
            out.ntFreeVirtualMemory != 0 &&
            out.ntProtectVirtualMemory != 0 &&
            out.ntDuplicateObject != 0;
    }

    void InitializeSyscallNumbers(const NtRoutines& nt) {
        g_ntOpen = nt.ntOpenProcess;
        g_ssn = GetSSN(nt.ntOpenProcess, kZwFunctionStub);
        g_ssn_read = GetSSN(nt.ntReadVirtualMemory, kZwFunctionStub);
        g_ssn_write = GetSSN(nt.ntWriteVirtualMemory, kZwFunctionStub);
        g_ssn_QSI = GetSSN(nt.ntQuerySystemInformation, kZwFunctionStub);
        g_ssn_thread = GetSSN(nt.ntCreateThreadEx, kZwFunctionStub);
        g_ssn_QIP = GetSSN(nt.ntQueryInformationProcess, kZwFunctionStub);
        g_ssn_allocate = GetSSN(nt.ntAllocateVirtualMemory, kZwFunctionStub);
        g_ssn_free = GetSSN(nt.ntFreeVirtualMemory, kZwFunctionStub);
        g_ssn_protect = GetSSN(nt.ntProtectVirtualMemory, kZwFunctionStub);
        g_ssn_duplicate = GetSSN(nt.ntDuplicateObject, kZwFunctionStub);
    }

    bool EnableDebugPrivilege() {
        HANDLE hToken = nullptr;
        LUID luid{};
        TOKEN_PRIVILEGES tp{};

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }

    bool ResolveNtdllFromPeb() {
        NTDLL::ldr = *reinterpret_cast<uintptr_t*>(pebBase + 0x18);
        const uintptr_t anchor = NTDLL::ldr + 0x10;
        uintptr_t current = *reinterpret_cast<uintptr_t*>(anchor);

        do {
            const uintptr_t bufferAddress = *reinterpret_cast<uintptr_t*>(current + 0x60);
            if (bufferAddress != 0) {
                const auto* dllName = reinterpret_cast<const wchar_t*>(bufferAddress);
                if (_wcsicmp(dllName, L"ntdll.dll") == 0) {
                    NTDLL::ntBase = *reinterpret_cast<uintptr_t*>(current + 0x30);
                    break;
                }
            }
            current = *reinterpret_cast<uintptr_t*>(current);
        } while (current != anchor);

        return NTDLL::ntBase != 0;
    }

    DWORD FindProcessIdByName(const wchar_t* imageName) {
        ULONG size = 0;
        Syscall_NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);

        void* buffer = std::malloc(static_cast<size_t>(size));
        if (!buffer)
            return 0;

        Syscall_NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);

        auto* walk = static_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
        DWORD pid = 0;

        for (;;) {
            if (walk->ImageName.Buffer != nullptr && _wcsicmp(walk->ImageName.Buffer, imageName) == 0) {
                pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(walk->UniqueProcessId));
                break;
            }
            if (walk->NextEntryOffset == 0)
                break;
            walk = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<uintptr_t>(walk) + walk->NextEntryOffset);
        }

        std::free(buffer);
        return pid;
    }

    bool QuerySystemHandlesWithGrowableBuffer(PVOID& buffer, SIZE_T& byteSize) {
        for (;;) {
            if (buffer == nullptr) {
                Syscall_NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &buffer, 0, &byteSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }

            const NTSTATUS st =
                Syscall_NtQuerySystemInformation(SystemExtendedHandleInformation, buffer,
                    static_cast<ULONG>(byteSize), nullptr);
            if (st == 0)
                return true;

            if (st == kNtStatusBufferTooSmall) {
                SIZE_T freed = 0;
                Syscall_NtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &buffer, &freed, MEM_RELEASE);
                buffer = nullptr;
                byteSize += 1024 * 256;
                continue;
            }

            return false;
        }
    }

    void FreeAllocation(PVOID& ptr) {
        if (!ptr)
            return;
        SIZE_T freed = 0;
        Syscall_NtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &ptr, &freed, MEM_RELEASE);
        ptr = nullptr;
    }

    uintptr_t FindRemoteModuleBase(HANDLE hProcess, uintptr_t remoteLdr, const wchar_t* moduleName) {
        const uintptr_t listHead = remoteLdr + 0x10;
        uintptr_t currentEntry = 0;
        NTSTATUS readSt =
            Syscall_NtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(listHead), &currentEntry, sizeof(currentEntry), nullptr);
        if (readSt != 0)
            return 0;

        while (currentEntry != listHead) {
            LDR_DATA_TABLE_ENTRY entry{};
            readSt = Syscall_NtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(currentEntry), &entry, sizeof(entry), nullptr);
            if (readSt != 0)
                break;

            const uintptr_t nextEntry = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);

            wchar_t* nameBuf = static_cast<wchar_t*>(std::malloc(entry.BaseDllName.Length + sizeof(wchar_t)));
            if (nameBuf) {
                readSt = Syscall_NtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, nameBuf, entry.BaseDllName.Length, nullptr);
                if (readSt == 0) {
                    nameBuf[entry.BaseDllName.Length / sizeof(wchar_t)] = L'\0';
                    if (_wcsicmp(moduleName, nameBuf) == 0) {
                        const uintptr_t base = reinterpret_cast<uintptr_t>(entry.DllBase);
                        std::free(nameBuf);
                        return base;
                    }
                }
                std::free(nameBuf);
            }

            if (nextEntry == 0)
                break;
            currentEntry = nextEntry;
        }

        return 0;
    }

    bool ResolveProcessObjectTypeIndex(USHORT& outIndex) {
        HANDLE hSelf = nullptr;
        CLIENT_ID selfCid = { reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetMyProcessId())), nullptr };
        OBJECT_ATTRIBUTES selfOa = { sizeof(selfOa) };
        selfOa.Length = sizeof(OBJECT_ATTRIBUTES);

        const NTSTATUS openSelf =
            Syscall_NtOpenProcess(&hSelf, PROCESS_QUERY_LIMITED_INFORMATION, &selfOa, &selfCid);
        if (openSelf != 0 || !hSelf)
            return false;

        PVOID handleBuf = nullptr;
        SIZE_T handleBufSize = 1024 * 1024;
        if (!QuerySystemHandlesWithGrowableBuffer(handleBuf, handleBufSize)) {
            CloseHandle(hSelf);
            FreeAllocation(handleBuf);
            return false;
        }

        auto* info = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(handleBuf);
        const ULONG_PTR myPid = static_cast<ULONG_PTR>(GetMyProcessId());
        const HANDLE selfVal = hSelf;

        for (ULONG i = 0; i < info->NumberOfHandles; ++i) {
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& e = info->Handles[i];
            if (e.UniqueProcessId == myPid && reinterpret_cast<HANDLE>(e.HandleValue) == selfVal) {
                outIndex = e.ObjectTypeIndex;
                CloseHandle(hSelf);
                FreeAllocation(handleBuf);
                return true;
            }
        }

        CloseHandle(hSelf);
        FreeAllocation(handleBuf);
        return false;
    }

    bool TryDuplicateFullControlHandle(
        HANDLE hDonor,
        PSYSTEM_HANDLE_INFORMATION_EX globalHandles,
        DWORD donorPid,
        DWORD targetPid,
        USHORT processTypeIndex,
        const wchar_t* candidateName,
        HANDLE& ioProcess) {

        for (ULONG i = 0; i < globalHandles->NumberOfHandles; ++i) {
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& entry = globalHandles->Handles[i];

            if (entry.UniqueProcessId != static_cast<ULONG_PTR>(donorPid) || entry.ObjectTypeIndex != processTypeIndex)
                continue;

            if (entry.GrantedAccess != kProcessFullControl)
                continue;

            HANDLE duplicated = nullptr;
            const NTSTATUS dupSt = Syscall_NtDuplicateObject(
                hDonor, reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry.HandleValue)),
                reinterpret_cast<HANDLE>(-1), &duplicated, 0, 0, kDuplicateSameAccess);

            if (dupSt != 0) {
                if (duplicated)
                    CloseHandle(duplicated);
                continue;
            }

            PROCESS_BASIC_INFORMATION pbi{};
            const NTSTATUS qipSt = Syscall_NtQueryInformationProcess(duplicated, 0, &pbi, sizeof(pbi), nullptr);

            if (qipSt == 0 && pbi.UniqueProcessId == static_cast<ULONG_PTR>(targetPid)) {
                ioProcess = duplicated;
                return true;
            }

            CloseHandle(duplicated);
        }

        return false;
    }

} // namespace



int main() {
    EnableDebugPrivilege();
    GetMyPeb();
    if (pebBase == 0) {
        std::printf("Ошибка: Не удалось получить PEB!\n");
        return 1;
    }

    if (!ResolveNtdllFromPeb())
        return 1;

    NtRoutines nt{};
    if (!ResolveNtRoutines(nt)) {
        std::printf("[-] Failed to resolve one or more Nt* routines.\n");
        return 1;
    }
    InitializeSyscallNumbers(nt);

    const uintptr_t ntDuplicate = nt.ntDuplicateObject;
    (void)ntDuplicate;

    const DWORD targetPid = FindProcessIdByName(L"cs2.exe");
    if (targetPid == 0) {
        std::printf("[-] cs2.exe not found.\n");
        return 1;
    }

    CLIENT_ID cid = {};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(targetPid));
    cid.UniqueThread = nullptr;

    OBJECT_ATTRIBUTES oa = {};
    oa.Length = sizeof(oa);

    HANDLE hProcess = nullptr;
    Syscall_NtOpenProcess(&hProcess, kOpenProcessDesiredAccess, &oa, &cid);

    PROCESS_BASIC_INFORMATION pbi{};
    Syscall_NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), nullptr);

    uintptr_t remoteLdr = 0;
    NTSTATUS readSt = Syscall_NtReadVirtualMemory(
        hProcess, reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + 0x18),
        &remoteLdr, sizeof(remoteLdr), nullptr);
    (void)readSt;

    const uintptr_t clientBase = FindRemoteModuleBase(hProcess, remoteLdr, L"client.dll");
    (void)clientBase;

    PVOID handleTableBuffer = nullptr;
    SIZE_T handleTableSize = 1024 * 1024;
    if (!QuerySystemHandlesWithGrowableBuffer(handleTableBuffer, handleTableSize)) {
        FreeAllocation(handleTableBuffer);
        return 1;
    }

    auto* const globalHandles = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(handleTableBuffer);

    const DWORD myPid = GetMyProcessId();

    ULONG procListSize = 0;
    Syscall_NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &procListSize);
    procListSize += 0x2000;

    PVOID procListBuffer = nullptr;
    SIZE_T procListAlloc = static_cast<SIZE_T>(procListSize);
    const NTSTATUS allocProc = Syscall_NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &procListBuffer, 0,
        &procListAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    USHORT processTypeIndex = 0;
    if (!ResolveProcessObjectTypeIndex(processTypeIndex)) {
        std::printf("[-] CRITICAL ERROR: Index not found! Check Admin permissions..\n");
        FreeAllocation(handleTableBuffer);
        FreeAllocation(procListBuffer);
        return 1;
    }

    if (allocProc == 0) {
        NTSTATUS qsiProc =
            Syscall_NtQuerySystemInformation(SystemProcessInformation, procListBuffer, procListSize, &procListSize);
        (void)qsiProc; // donor sweep runs even if first QSI is flaky

        static const wchar_t* const kDonors[] = {
            L"csrss.exe", L"lsass.exe", L"Steam.exe", L"Discord.exe", L"svchost.exe",
        };

        bool duplicated = false;

        for (const wchar_t* donorName : kDonors) {
            if (duplicated)
                break;

            auto* scan = static_cast<PSYSTEM_PROCESS_INFORMATION>(procListBuffer);
            for (;;) {
                if (duplicated)
                    break;

                if (scan->ImageName.Buffer && _wcsicmp(scan->ImageName.Buffer, donorName) == 0) {
                    const DWORD donorPid =
                        static_cast<DWORD>(reinterpret_cast<uintptr_t>(scan->UniqueProcessId));

                    if (donorPid != myPid) {
                        CLIENT_ID dCid = { reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(donorPid)), nullptr };
                        OBJECT_ATTRIBUTES dOa = { sizeof(dOa) };

                        HANDLE hDonor = nullptr;
                        if (Syscall_NtOpenProcess(&hDonor, PROCESS_DUP_HANDLE, &dOa, &dCid) == 0 && hDonor) {
                            HANDLE previous = hProcess;
                            if (TryDuplicateFullControlHandle(hDonor, globalHandles, donorPid, targetPid,
                                processTypeIndex, donorName, hProcess)) {
                                if (previous)
                                    CloseHandle(previous);
                                duplicated = true;
                                CloseHandle(hDonor);
                                break;
                            }
                            CloseHandle(hDonor);
                        }
                    }
                }

                if (scan->NextEntryOffset == 0)
                    break;
                scan = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                    reinterpret_cast<uintptr_t>(scan) + scan->NextEntryOffset);
            }
        }
    }

    FreeAllocation(procListBuffer);
    FreeAllocation(handleTableBuffer);

   
    return 0;
}
