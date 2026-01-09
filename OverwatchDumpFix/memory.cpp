#include "memory.h"

#include <vector>

#include "ntdll.h"
#include "plugin.h"

static DWORD systemAllocationGranularity = 0;

static void SetSystemAllocationGranularity()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    systemAllocationGranularity = si.dwAllocationGranularity;
}

static bool _RemapViewOfSection(SIZE_T BaseAddress, SIZE_T RegionSize, PVOID CopyBuffer, std::vector<SIZE_T>* ReplacedViewBases = nullptr)
{
    // Step 1: Backup the view's content (read region by region to handle different protections)
    SIZE_T currentOffset = 0;
    while (currentOffset < RegionSize) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(debuggee.hProcess, PVOID(BaseAddress + currentOffset), &mbi, sizeof(mbi))) {
            pluginLog("Error: VirtualQueryEx failed at %p: %d.\n", BaseAddress + currentOffset, GetLastError());
            return false;
        }
        
        // Calculate how much to read from this region
        SIZE_T regionReadSize = mbi.RegionSize - (BaseAddress + currentOffset - SIZE_T(mbi.BaseAddress));
        if (currentOffset + regionReadSize > RegionSize) {
            regionReadSize = RegionSize - currentOffset;
        }
        
        // Skip regions that can't be read (not committed or no access)
        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) {
            pluginLog("Warning: Skipping unreadable region at %p (State: 0x%X, Protect: 0x%X), filling with zeros.\n", 
                BaseAddress + currentOffset, mbi.State, mbi.Protect);
            RtlZeroMemory((PBYTE)CopyBuffer + currentOffset, regionReadSize);
        } else {
            NTSTATUS readStatus = 0;
            if (!memory::util::RemoteRead(BaseAddress + currentOffset, (PBYTE)CopyBuffer + currentOffset, regionReadSize, &readStatus)) {
                pluginLog("Error: failed to backup view at %p (size: 0x%llX): NTSTATUS 0x%08X.\n", 
                    BaseAddress + currentOffset, regionReadSize, readStatus);
                return false;
            }
        }
        
        currentOffset += regionReadSize;
    }

    // Get views to unmap
    const std::vector<SIZE_T> replacedViewBases = ReplacedViewBases ?
        *ReplacedViewBases : std::vector<SIZE_T>{ BaseAddress };

    // Step 2: Unmap the existing view(s) to free the address space
    for (const auto view : replacedViewBases) {
        NTSTATUS status = NtUnmapViewOfSection(debuggee.hProcess, PVOID(view));
        if (!NT_SUCCESS(status)) {
            pluginLog("Error: NtUnmapViewOfSection failed for %p: 0x%08X\n", view, status);
            return false;
        }
    }

    // Step 3: Create a section to map the new view
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionMaxSize = {};
    sectionMaxSize.QuadPart = memory::util::RoundUpToAllocationGranularity(RegionSize);
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionMaxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (!NT_SUCCESS(status)) {
        pluginLog("Error: NtCreateSection failed: 0x%08X\n", status);
        return false;
    }

    // Step 4: Map the new view at the target address (which is now free)
    PVOID viewBase = PVOID(BaseAddress);
    LARGE_INTEGER sectionOffset = {};
    SIZE_T viewSize = RegionSize;
    status = NtMapViewOfSection(hSection,
        debuggee.hProcess,
        &viewBase,
        0,
        RegionSize,
        &sectionOffset,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READWRITE);

    // Close section handle
    CloseHandle(hSection);

    if (!NT_SUCCESS(status)) {
        pluginLog("Error: NtMapViewOfSection failed for %p: 0x%08X\n", BaseAddress, status);
        return false;
    }

    // Verify mapping succeeded at the right address
    if (viewBase != PVOID(BaseAddress) || viewSize < RegionSize) {
        pluginLog("Error: View mapped at wrong address or size: requested %p:%llX, got %p:%llX\n",
            BaseAddress, RegionSize, viewBase, viewSize);
        NtUnmapViewOfSection(debuggee.hProcess, viewBase);
        return false;
    }

    // Step 5: Restore the view's content
    NTSTATUS writeStatus = 0;
    if (!memory::util::RemoteWrite(BaseAddress, CopyBuffer, RegionSize, &writeStatus)) {
        pluginLog("Error: failed to restore view at %p: NTSTATUS 0x%08X.\n", BaseAddress, writeStatus);
        return false;
    }

    return true;
}

bool memory::RemapViewOfSection(size_t base_address, size_t region_size) {
    PVOID copy_buffer = VirtualAlloc(NULL, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!copy_buffer)
        return false;

    bool result = _RemapViewOfSection(base_address, region_size, copy_buffer);
    VirtualFree(copy_buffer, 0, MEM_RELEASE);
    return result;
}

//bool memory::CombineAdjacentViews(const std::vector<MEMORY_BASIC_INFORMATION>& Views)
//{
//    // Check for consecutive views.
//    SIZE_T combinedSize = 0;
//    std::vector<SIZE_T> replacedViewBases;
//    for (int i = 0; i < Views.size(); i++) {
//        if (combinedSize && SIZE_T(Views[i - 1].BaseAddress) + combinedSize != SIZE_T(Views[i].BaseAddress)) {
//            pluginLog("Error: attempted to combine non-consecutive views.\n");
//            return false;
//        }
//        combinedSize += Views[i].RegionSize;
//        replacedViewBases.push_back(SIZE_T(Views[i].BaseAddress));
//    }
//    PVOID copybuf = VirtualAlloc(NULL, combinedSize, MEM_COMMIT | MEM_RESERVE,
//                                 PAGE_EXECUTE_READWRITE);
//    if (!copybuf)
//        return false;
//    bool result = _RemapViewOfSection(SIZE_T(Views[0].BaseAddress), combinedSize,
//                                      copybuf, &replacedViewBases);
//    VirtualFree(copybuf, 0, MEM_RELEASE);
//    return result;
//}

///////////////////////////////////////////////////////////////////////////////
// util

bool memory::util::RemoteWrite(SIZE_T BaseAddress, PVOID DestinationAddress, SIZE_T WriteSize, NTSTATUS* pStatus)
{
    SIZE_T numberOfBytesWritten = 0;
    NTSTATUS status = NtWriteVirtualMemory(
        debuggee.hProcess,
        PVOID(BaseAddress),
        DestinationAddress,
        WriteSize,
        &numberOfBytesWritten);
    if (pStatus)
        *pStatus = status;
    return status == STATUS_SUCCESS && numberOfBytesWritten == WriteSize;
}

bool memory::util::RemoteRead(SIZE_T BaseAddress, const PVOID SourceAddress,
                              SIZE_T ReadSize, NTSTATUS* pStatus)
{
    SIZE_T numberOfBytesRead = 0;
    NTSTATUS status = NtReadVirtualMemory(
        debuggee.hProcess,
        PVOID(BaseAddress),
        SourceAddress,
        ReadSize,
        &numberOfBytesRead);
    if (pStatus)
        *pStatus = status;
    return status == STATUS_SUCCESS && numberOfBytesRead == ReadSize;
}

bool memory::util::GetPageInfo(size_t base_address, size_t range_size,
                               std::vector<MEMORY_BASIC_INFORMATION>& page_info)
{
    page_info.clear();
    const size_t end_address = base_address + range_size;
    for (size_t ea = base_address; ea < end_address; /**/) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(debuggee.hProcess, PVOID(ea), &mbi, sizeof(mbi)))
            return false;
        page_info.push_back(mbi);
        ea += mbi.RegionSize;
    }
    return page_info.size() > 0;
}

SIZE_T memory::util::RoundUpToAllocationGranularity(SIZE_T Size)
{
    if (!systemAllocationGranularity)
        SetSystemAllocationGranularity();
    return ((Size + systemAllocationGranularity - 1) &
            ~(systemAllocationGranularity - 1));
}

SIZE_T memory::util::AlignToAllocationGranularity(SIZE_T Address)
{
    if (!systemAllocationGranularity)
        SetSystemAllocationGranularity();
    return (Address & ~(systemAllocationGranularity - 1));
}
