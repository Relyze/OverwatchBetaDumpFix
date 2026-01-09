#include "fix_dump.h"

#include <Psapi.h>
#include <Shlwapi.h>

#include <vector>

#include "memory.h"
#include "ntdll.h"
#include "import_deobfuscation.h"

bool fixdump::current::FixOverwatch()
{
    BUFFERED_PE_HEADER peHeader;
    if (!GetOverwatchPeHeader(peHeader)) {
        pluginLog("Error: failed to get Overwatch's PE header.\n");
        return false;
    }

    std::vector<MEMORY_BASIC_INFORMATION> memoryViews;
    if (!memory::util::GetPageInfo(debuggee.imageBase, debuggee.imageSize,
                                   memoryViews)) {
        pluginLog("Error: failed to get memory views.\n");
        return false;
    }

    pluginLog("Found %d views:\n", memoryViews.size());
    pluginLog("             Address                Size  Protection\n");

    for (auto& view_info : memoryViews)
    {
        pluginLog("    %p    %16llX    %8X\n",
            view_info.BaseAddress,
            view_info.RegionSize,
            view_info.Protect);
    }

    bool remapSuccess = memory::RemapViewOfSection(size_t(debuggee.imageBase), debuggee.imageSize);
    if (!remapSuccess) {
        pluginLog("Error: failed to remap entire image at %p.\n", debuggee.imageBase);
        return false;
    }

    FixPeHeader(peHeader);

    if (!RestorePeHeader(peHeader)) {
        pluginLog("Error: failed to write PE Header to %p.\n", debuggee.imageBase);
        return false;
    }

    REMOTE_PE_HEADER restoredPeHeader{};
    if (!FillRemotePeHeader(debuggee.hProcess, debuggee.imageBase, restoredPeHeader)) {
        pluginLog("Error: restored PE header at %p was invalid.\n", debuggee.imageBase);
        return false;
    }

    if (!IdfDeobfuscateImportAddressTable(
            debuggee.hProcess,
            debuggee.imageBase,
            debuggee.imageSize,
            restoredPeHeader)) {
        pluginLog("Error: failed to rebuild imports.\n");
        return false;
    }

    if (!SplitSections(restoredPeHeader)) {
        pluginLog("Error: failed to split pe sections.\n");
        return false;
    }

    return true;
}

//
// GetOverwatchImageSize
//
// This function acquires the image size of the debuggee via the debuggee's
//  LDR_DATA_TABLE_ENTRY in the PEB.
//
// NOTE All addresses and pointer values refer to the virtual address space of
//  the debuggee process.
//
BOOL fixdump::current::GetOverwatchImageSize(HANDLE hProcess, PULONG pcbImageSize)
{
    PVOID pPeb = NULL;
    PVOID pPebLdr = NULL;
    ULONG_PTR PebLdr = 0;
    PVOID pInMemoryOrderModuleList = NULL;
    LIST_ENTRY InMemoryOrderModuleList = {};
    PLDR_DATA_TABLE_ENTRY pOverwatchLdrDataEntry = NULL;
    LDR_DATA_TABLE_ENTRY OverwatchLdrDataEntry = {};
    BOOL status = TRUE;

    // Zero out parameters.
    *pcbImageSize = 0;

    //
    // Get the address of the debuggee's PEB.
    //
    pPeb = (PVOID)DbgGetPebAddress(DbgGetProcessId());
    if (!pPeb)
    {
        ERR_PRINT("DbgGetPebAddress failed.\n");
        status = FALSE;
        goto exit;
    }

    DBG_PRINT("pPeb:        %p\n", pPeb);

    //
    // Read the value of the remote PEB.Ldr field.
    //
    pPebLdr = (PVOID)((ULONG_PTR)pPeb + FIELD_OFFSET(PEB, LoaderData));

    DBG_PRINT("pPebLdr:     %p\n", pPebLdr);

    status = ReadProcessMemory(
        hProcess,
        pPebLdr,
        &PebLdr,
        sizeof(PebLdr),
        NULL);
    if (!status)
    {
        ERR_PRINT("ReadProcessMemory failed: %u (ldr)\n", GetLastError());
        goto exit;
    }

    DBG_PRINT("PebLdr:      %p\n", PebLdr);

    //
    // Read the values of the remote PEB.Ldr.InMemoryOrderModuleList field.
    //
    pInMemoryOrderModuleList = (PVOID)(
        PebLdr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList));

    DBG_PRINT("pInMemoryOrderModuleList:            %p\n",
        pInMemoryOrderModuleList);

    status = ReadProcessMemory(
        hProcess,
        pInMemoryOrderModuleList,
        &InMemoryOrderModuleList,
        sizeof(InMemoryOrderModuleList),
        NULL);
    if (!status)
    {
        ERR_PRINT("ReadProcessMemory failed: %u (InMemoryOrderModuleList)\n",
            GetLastError());
        goto exit;
    }

    DBG_PRINT("InMemoryOrderModuleList.Flink:       %p\n",
        InMemoryOrderModuleList.Flink);

    //
    // Read the LDR_DATA_TABLE_ENTRY for the debuggee process.
    //
    pOverwatchLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)(
        (ULONG_PTR)InMemoryOrderModuleList.Flink -
        FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

    DBG_PRINT("pOverwatchLdrDataEntry:              %p\n", PebLdr);

    status = ReadProcessMemory(
        hProcess,
        pOverwatchLdrDataEntry,
        &OverwatchLdrDataEntry,
        sizeof(OverwatchLdrDataEntry),
        NULL);
    if (!status)
    {
        ERR_PRINT("ReadProcessMemory failed: %u (entry)\n", GetLastError());
        goto exit;
    }

    //
    // TODO Validate LDR_DATA_TABLE_ENTRY.FullDllName against
    //  PEB.ProcessParameters.ImagePathName.
    //

    //
    // Verify that the image size from the ldr entry is not zero.
    //
    if (!OverwatchLdrDataEntry.SizeOfImage)
    {
        ERR_PRINT("LdrDataEntry.SizeOfImage was zero.\n");
        status = FALSE;
        goto exit;
    }

    DBG_PRINT("OverwatchLdrDataEntry.SizeOfImage:   0x%IX\n",
        OverwatchLdrDataEntry.SizeOfImage);

    // Set out parameters.
    *pcbImageSize = OverwatchLdrDataEntry.SizeOfImage;

exit:
    return status;
}


//bool fixdump::current::GetOverwatchPeHeader(BUFFERED_PE_HEADER& PeHeader) {
//    std::ifstream in(debuggee.image_name, std::ios::binary);
//    if (!in.is_open())
//        return false;
//    unsigned char buffer[PE_HEADER_SIZE] = {};
//    in.read((char*)buffer, PE_HEADER_SIZE);
//    return in && FillBufferedPeHeader(buffer, PE_HEADER_SIZE, PeHeader);
//}

bool fixdump::current::GetOverwatchPeHeader(BUFFERED_PE_HEADER& PeHeader)
{
    wchar_t overwatchPath[MAX_MODULE_SIZE] = {};
    if (!GetModuleFileNameExW(debuggee.hProcess,
                              nullptr,
                              overwatchPath,
                              MAX_MODULE_SIZE)) {
        pluginLog("Error: failed to get Overwatch's path.\n");
        return false;
    }

    HANDLE hOverwatchFile = CreateFileW(overwatchPath,
                                        GENERIC_READ,
                                        FILE_SHARE_READ,
                                        nullptr,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        nullptr);
    if (hOverwatchFile == INVALID_HANDLE_VALUE) {
        pluginLog("Error: failed to open Overwatch.exe while getting pe header.\n");
        return false;
    }

    DWORD numBytesRead = 0;
    if (!ReadFile(hOverwatchFile,
                  LPVOID(PeHeader.rawData),
                  PE_HEADER_SIZE,
                  &numBytesRead,
                  nullptr)) {
        pluginLog("Error: failed to read Overwatch.exe.\n");
        CloseHandle(hOverwatchFile);
        return false;
    }

    // HACK 4.29.2017: pe header code needs a rewrite and so does this.
    if (!FillPeHeader(SIZE_T(PeHeader.rawData), PeHeader)) {
        pluginLog("Error: failed to create pe header from read buffer.\n");
        CloseHandle(hOverwatchFile);
        return false;
    }

    CloseHandle(hOverwatchFile);
    return true;
}

void fixdump::current::FixPeHeader(BUFFERED_PE_HEADER& PeHeader)
{
    PeHeader.optionalHeader->ImageBase = debuggee.imageBase;
}

BOOL fixdump::current::RestorePeHeader(BUFFERED_PE_HEADER& PeHeader)
{
    return memory::util::RemoteWrite(debuggee.imageBase, PVOID(PeHeader.rawData), PE_HEADER_SIZE);
}

bool fixdump::current::SplitSections(const REMOTE_PE_HEADER& PeHeader)
{
    auto SetPageProtection = [](size_t BaseAddress,
                                size_t RegionSize,
                                DWORD NewProtection)
    {
        pluginLog("Restoring protection at %p (%llX) to %X.\n", BaseAddress,
                  RegionSize, NewProtection);

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(debuggee.hProcess, PVOID(BaseAddress),
                              RegionSize, NewProtection, &oldProtection)) {
            pluginLog("Warning: failed to restore view protection at %p (%llX), error code %d.\n",
                      BaseAddress, RegionSize, GetLastError());
        }
    };

    PIMAGE_SECTION_HEADER textSection = GetPeSectionByName(PeHeader, ".text");
    PIMAGE_SECTION_HEADER rdataSection = GetPeSectionByName(PeHeader, ".rdata");
    if (!textSection || !rdataSection) {
        pluginLog("Error: failed to find .text or .rdata section header pointers.\n");
        return false;
    }

    SetPageProtection(debuggee.imageBase,
                      PE_HEADER_SIZE,
                      PAGE_READONLY);
    SetPageProtection(debuggee.imageBase + textSection->VirtualAddress,
                      textSection->Misc.VirtualSize,
                      PAGE_EXECUTE_READ);
    // BUG 4.18.2017: this fails with error code 298 ERROR_TOO_MANY_POSTS. I fixed this
    // issue with RPM / WPM by using custom wrappers instead of the plugin sdk
    // wrappers. Adding a Sleep(X000) before this call changes the error code to
    // 487 ERROR_INVALID_ADDRESS. I have no idea why this happens or how to fix it.
    // Even if it fails .rdata should still be separated from .text as long as
    // the call above succeeds.
    SetPageProtection(debuggee.imageBase + rdataSection->VirtualAddress,
                      rdataSection->Misc.VirtualSize,
                      PAGE_READONLY);

    return true;
}