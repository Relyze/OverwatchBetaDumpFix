#include "import_deobfuscation.h"

#include <malloc.h>

#include "ntdll.h"
#include "plugin.h"

#include "zydis/Zydis.h"

//
// Define an arbitrary limit to the amount of IAT entries we parse before
//  assuming failure.
//
#define IAT_ENTRY_LIMIT 1500

//
// We use two pages for the emulation buffer so that we do not have the handle
//  edge cases where the diassembler incorrectly reads past the page boundary.
//
#define EMULATION_BUFFER_SIZE   (PAGE_SIZE * 2)

//
// IdfpGetIatEntries
//
// Copy the import address table from the remote process into a local buffer.
//
// On success, callers must free 'ppIatEntries' via 'HeapFree'.
//
_Check_return_
BOOL
IdfpGetIatEntries(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ ULONG_PTR IatSection,
    _In_ ULONG cbIatSection,
    _Outptr_ PULONG_PTR* ppIatEntries,
    _Out_ PSIZE_T pcIatEntries
)
{
    PULONG_PTR pIatEntries = NULL;
    ULONG cbIatEntries = 0;
    ULONG cLastEntry = 0;
    SIZE_T cIatEntries = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *ppIatEntries = NULL;
    *pcIatEntries = 0;

    //
    // Lazily clamp our search range.
    //
    cbIatEntries = min(cbIatSection, IAT_ENTRY_LIMIT * sizeof(*pIatEntries));
    cLastEntry = cbIatEntries / sizeof(ULONG_PTR);

    pIatEntries = (PULONG_PTR)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        cbIatEntries);
    if (!pIatEntries)
    {
        ERR_PRINT("HeapAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }
    MEMORY_BASIC_INFORMATION memInfo;
    if (VirtualQueryEx(hProcess, (PVOID)IatSection, &memInfo, sizeof(memInfo)))
    {
        INF_PRINT("Memory region info at %p:\n", IatSection);
        INF_PRINT("  Base Address: %p\n", memInfo.BaseAddress);
        INF_PRINT("  Region Size: 0x%IX\n", memInfo.RegionSize);
        INF_PRINT("  State: 0x%X\n", memInfo.State);
        INF_PRINT("  Protect: 0x%X\n", memInfo.Protect);

        // Only read what's actually available in this region
        cbIatEntries = min(cbIatEntries, (ULONG)memInfo.RegionSize - (ULONG)((ULONG_PTR)IatSection - (ULONG_PTR)memInfo.BaseAddress));
        INF_PRINT("  Adjusted read size: 0x%X\n", cbIatEntries);
	}
	else
	{
		ERR_PRINT("VirtualQueryEx failed: %u\n", GetLastError());
		goto exit;
	}


    //
    // Copy our IAT search range into a local buffer.
    //
    status = ReadProcessMemory(
        hProcess,
        (PVOID)IatSection,
        pIatEntries,
        cbIatEntries,
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "ReadProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            IatSection,
            cbIatEntries);
        goto exit;
    }

    for (ULONG_PTR i = 0; i < cLastEntry && pIatEntries[i] < ImageBase; ++i)
    {
        cIatEntries++;
    }

    // Set out parameters.
    *ppIatEntries = pIatEntries;
    *pcIatEntries = cIatEntries;

exit:
    if (!status)
    {
        if (pIatEntries)
        {
            if (!HeapFree(GetProcessHeap(), 0, pIatEntries))
            {
                ERR_PRINT("HeapFree failed: %u\n", GetLastError());
            }
        }
    }

    return status;
}

//
// IdfpDeobfuscateEntry
//
_Check_return_
BOOL
IdfpDeobfuscateEntry(
    _In_ PVOID pEmulationBuffer,
    _In_ PVOID pDeobfuscationPage,
    _In_ ULONG_PTR EntryOffset,
    _Out_ PULONG_PTR pDeobfuscatedEntry
)
{
    ULONG_PTR IntermediateEntry = 0;
    ULONG_PTR DeobfuscatedEntry = 0;
    BOOL status = TRUE;

    // Zero out parameters.
    *pDeobfuscatedEntry = NULL;

    // Storing r10 value during 0xBA (mov r10, imm64) operation
    ZyanU64 r10 = 0;
    ZyanU64 r11 = 0;

    ZydisDecoder decoder;
    ZydisDecoderContext ctx;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);


    ZyanUSize length = EMULATION_BUFFER_SIZE;
    ZydisDecodedInstruction instruction;

    ZyanUSize offset = EntryOffset;
    ZyanU64 buffer = (ZyanU64)pEmulationBuffer;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &ctx, (ZyanU8*)(buffer + offset), length - offset, &instruction)))
    {
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
        ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE);


        // mov r10, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[0].reg.value == ZYDIS_REGISTER_R10)
        {
			// Store r10 value from the operation (used later)
			r10 = operands[1].imm.value.u;
			INF_PRINT("    r10: %llx", r10);
		}

        // mov r11, value
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[0].reg.value == ZYDIS_REGISTER_R11)
		{
			r11 = operands[1].imm.value.u;
			INF_PRINT("    r11: %llx", operands[1].imm.value.u);
		}

        // mov rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[0].reg.value == ZYDIS_REGISTER_RAX)
        {
            IntermediateEntry = operands[1].imm.value.u;
            INF_PRINT("    mov: rax = %llx", operands[1].imm.value.u);
        }

        // add rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD && operands[0].reg.value == ZYDIS_REGISTER_RAX)
        {
            INF_PRINT("    add: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.u, IntermediateEntry + operands[1].imm.value.s);
			IntermediateEntry += operands[1].imm.value.s;
		}

        // sub rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_SUB && operands[0].reg.value == ZYDIS_REGISTER_RAX)
		{
            INF_PRINT("    sub: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.u, IntermediateEntry - operands[1].imm.value.s);
            IntermediateEntry -= operands[1].imm.value.s;
        }

        // xor rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_XOR && operands[0].reg.value == ZYDIS_REGISTER_RAX)
        {
            INF_PRINT("    xor: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.s, IntermediateEntry ^ operands[1].imm.value.s);
			IntermediateEntry ^= operands[1].imm.value.s;
		}

        // xor rax, r11
		if (instruction.mnemonic == ZYDIS_MNEMONIC_XOR && operands[0].reg.value == ZYDIS_REGISTER_RAX && operands[1].reg.value == ZYDIS_REGISTER_R11)
		{
			INF_PRINT("    xor: %llx, %llx = %llx", IntermediateEntry, r11, IntermediateEntry ^ r11);
			IntermediateEntry ^= r11;
		}

        // imul rax, r10
        if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL && operands[0].reg.value == ZYDIS_REGISTER_RAX && operands[1].reg.value == ZYDIS_REGISTER_R10)
        {
			// Handle our errors, just in case so we don't have to look forever later
            if (r10 == 0)
            {
				ERR_PRINT("    r10 == 0, opcode: 0x%X\n", instruction.opcode);
				status = FALSE;
				goto exit;
			}
            else
            {
				INF_PRINT("    imul: %llx, %llx = %llx", IntermediateEntry, r10, IntermediateEntry * r10);
				IntermediateEntry *= r10;
			}
		}

        // rol rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_ROL && operands[0].reg.value == ZYDIS_REGISTER_RAX)
        {
            INF_PRINT("    rol: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.u, _rotl64(IntermediateEntry, operands[1].imm.value.u));
            IntermediateEntry = _rotl64(IntermediateEntry, operands[1].imm.value.u);
        }

		// ror rax, value
		if (instruction.mnemonic == ZYDIS_MNEMONIC_ROR && operands[0].reg.value == ZYDIS_REGISTER_RAX)
		{
			INF_PRINT("    ror: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.u, _rotr64(IntermediateEntry, operands[1].imm.value.u));
			IntermediateEntry = _rotr64(IntermediateEntry, operands[1].imm.value.u);
		}

		// shr rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_SHR && operands[0].reg.value == ZYDIS_REGISTER_RAX) {
			INF_PRINT("    shr: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.u, IntermediateEntry >> operands[1].imm.value.u);
			IntermediateEntry >>= operands[1].imm.value.u;
        }

		// shl rax, value
        if (instruction.mnemonic == ZYDIS_MNEMONIC_SHL && operands[0].reg.value == ZYDIS_REGISTER_RAX) {
			INF_PRINT("    shl: %llx, %llx = %llx", IntermediateEntry, operands[1].imm.value.u, IntermediateEntry << operands[1].imm.value.u);
			IntermediateEntry <<= operands[1].imm.value.u;
        }

        // relative jump (0xE9)
        if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP && operands[0].reg.value == ZYDIS_REGISTER_RAX)
        {
            INF_PRINT("    jmp: %llx\n", IntermediateEntry);
            DeobfuscatedEntry = IntermediateEntry;
        } else if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            // follow the relative jump, by calculating the absolute address,  ZydisCalcAbsoluteAddress	(const ZydisDecodedInstruction* instruction,  const ZydisDecodedOperand* operand,  ZyanU64 	runtime_address, ZyanU64* result_address)
            ZyanU64* absoluteAddress = 0;

            const uintptr_t instructionPointer = (uintptr_t)buffer + offset;
            INF_PRINT("    instructionPointer: %llx\n", instructionPointer);
            const int64_t relativePointer = operands[0].imm.value.s;
            INF_PRINT("    relativePointer: %llx\n", relativePointer);
            const uintptr_t finalDestination = instructionPointer + relativePointer;
            INF_PRINT("    jmp: %llx\n", finalDestination);
            offset += relativePointer;
        }

        // Exit if deobfuscation is complete.
        if (DeobfuscatedEntry)
            break;

        offset += instruction.length;
    }

    //
    if (!DeobfuscatedEntry)
    {
        ERR_PRINT("Failed to deobfuscate entry.\n");
        status = FALSE;
        goto exit;
    }

    // Set out parameters.
    *pDeobfuscatedEntry = DeobfuscatedEntry;

exit:
    return status;
}


//
// IdfpDeobfuscateIatEntries
//
// Deobfuscate the elements in 'pIatEntries'. Each obfuscated pointer is
//  overwritten with its deobfuscated import address in the remote process.
//
_Check_return_
BOOL
IdfpDeobfuscateIatEntries(
    _In_ HANDLE hProcess,
    _Inout_ PULONG_PTR pIatEntries,
    _In_ SIZE_T cIatEntries
)
{
    PVOID pEmulationBuffer = NULL;
    PVOID pDeobfuscationPage = NULL;
    ULONG_PTR EntryOffset = 0;
    ULONG_PTR DeobfuscatedEntry = 0;
    SIZE_T cDeobfuscatedEntries = 0;
    BOOL status = TRUE;

    //
    // Allocate a page aligned buffer to store the contents of the
    //  deobfuscation page in the remote process.
    //
    pEmulationBuffer = _aligned_malloc(EMULATION_BUFFER_SIZE, PAGE_SIZE);
    if (!pEmulationBuffer)
    {
        ERR_PRINT("_aligned_malloc failed: %d\n", errno);
        status = FALSE;
        goto exit;
    }

    //
    // Deobfuscate all IAT entries.
    //
    for (SIZE_T i = 0; i < cIatEntries; ++i)
    {
        //
        // Skip null entries.
        //
        if (!pIatEntries[i])
        {
            continue;
        }

        //
        // Reset the emulation buffer for each entry.
        //
        RtlSecureZeroMemory(pEmulationBuffer, EMULATION_BUFFER_SIZE);

        //
        // Calculate the address of the page containing the deobfuscation code
        //  for this entry.
        //
        pDeobfuscationPage = (PVOID)ALIGN_DOWN_BY(pIatEntries[i], PAGE_SIZE);

        //
        // Read the first page (required).
        //
        status = ReadProcessMemory(
            hProcess,
            pDeobfuscationPage,
            pEmulationBuffer,
            PAGE_SIZE,
            NULL);
        if (!status)
        {
            ERR_PRINT(
                "ReadProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
                GetLastError(),
                pDeobfuscationPage,
                PAGE_SIZE);
            goto exit;
        }

        //
        // Try to read the second page to handle entries that span page
        // boundaries (e.g., entry at offset 0xFF6 where instructions continue
        // into the next page). This read is optional - if it fails, we proceed
        // with just the first page.
        //
        ReadProcessMemory(
            hProcess,
            (PVOID)((ULONG_PTR)pDeobfuscationPage + PAGE_SIZE),
            (PVOID)((ULONG_PTR)pEmulationBuffer + PAGE_SIZE),
            PAGE_SIZE,
            NULL);

        EntryOffset = BYTE_OFFSET(pIatEntries[i]);

        INF_PRINT("Deobfuscating entry: %p\n", pIatEntries[i]);
        INF_PRINT("    DeobfuscationPage: %p\n", pDeobfuscationPage);
        INF_PRINT("    EntryOffset:       0x%IX\n", EntryOffset);

        status = IdfpDeobfuscateEntry(
            pEmulationBuffer,
            pDeobfuscationPage,
            EntryOffset,
            &DeobfuscatedEntry);
        if (!status)
        {
            ERR_PRINT("IdfpDeobfuscateEntry failed for entry: %p.\n",
                pIatEntries[i]);
            goto exit;  
        }
        INF_PRINT("DeobfuscatedEntry: %p", DeobfuscatedEntry);
        INF_PRINT("");
        //
        // Update the entry.
        //
        pIatEntries[i] = DeobfuscatedEntry;

        cDeobfuscatedEntries++;
    }

    INF_PRINT("Successfully deobfuscated %Iu IAT entries.\n",
        cDeobfuscatedEntries);

exit:
    if (pEmulationBuffer)
    {
        _aligned_free(pEmulationBuffer);
    }

    return status;
}


//
// IdfpPatchImportAddressTable
//
_Check_return_
BOOL
IdfpPatchImportAddressTable(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ImageBase,
    _In_ const REMOTE_PE_HEADER& RemotePeHeader,
    _In_ ULONG_PTR IatSection,
    _In_ PULONG_PTR pDeobfuscatedIatEntries,
    _In_ SIZE_T cIatEntries

)
{
    PIMAGE_DATA_DIRECTORY pImageDataDirectoryIat = NULL;
    IMAGE_DATA_DIRECTORY IatDataDirectoryPatch = {};
    SIZE_T cbIatEntries = 0;
    BOOL status = TRUE;

    INF_PRINT("Patching the import address table...\n");

    cbIatEntries = cIatEntries * sizeof(ULONG_PTR);

    //
    // Patch the IAT data directory entry in the remote pe header to reflect
    //  our deobfuscated IAT. We must do this so that Scylla can correctly
    //  rebuild the IAT.
    //
    // Calculate the address of the remote IAT data directory entry.
    //
    pImageDataDirectoryIat = (PIMAGE_DATA_DIRECTORY)(ImageBase +  (ULONG_PTR)&RemotePeHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] - (ULONG_PTR)&RemotePeHeader.dosHeader);

    //
    // Sanity check.
    //
    if (cbIatEntries > MAXDWORD)
    {
        ERR_PRINT("Unexpected IAT entries size: 0x%IX\n", cbIatEntries);
        status = FALSE;
        goto exit;
    }

    //
    // Initialize the data directory patch.
    //
    IatDataDirectoryPatch.VirtualAddress = (DWORD)(IatSection - ImageBase);
    IatDataDirectoryPatch.Size = (DWORD)cbIatEntries;

    INF_PRINT("Patching the IAT data directory entry at %p:\n", pImageDataDirectoryIat);
    INF_PRINT("    VirtualAddress:  0x%X\n", IatDataDirectoryPatch.VirtualAddress);
    INF_PRINT("    Size:            0x%X\n", IatDataDirectoryPatch.Size);

    //
    // Write the patch to the remote process.
    //
    status = WriteProcessMemory(
        hProcess,
        pImageDataDirectoryIat,
        &IatDataDirectoryPatch,
        sizeof(IatDataDirectoryPatch),
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "WriteProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            pImageDataDirectoryIat,
            sizeof(IatDataDirectoryPatch));
        goto exit;
    }

    //
    // Overwrite the obfuscated IAT in the remote process with the deobfuscated
    //  table.
    //
    status = WriteProcessMemory(
        hProcess,
        (PVOID)IatSection,
        pDeobfuscatedIatEntries,
        cbIatEntries,
        NULL);
    if (!status)
    {
        ERR_PRINT(
            "WriteProcessMemory failed: %u. (Address = %p, Size = 0x%IX)\n",
            GetLastError(),
            IatSection,
            cbIatEntries);
        goto exit;
    }

    INF_PRINT("Successfully patched remote IAT.\n");

exit:
    return status;
}


//
// IdfDeobfuscateImportAddressTable
//
_Use_decl_annotations_
BOOL
IdfDeobfuscateImportAddressTable(
    HANDLE hProcess,
    ULONG_PTR ImageBase,
    ULONG cbImageSize,
    const REMOTE_PE_HEADER& RemotePeHeader
)
{
    PIMAGE_SECTION_HEADER pIatSectionHeader = NULL;
    ULONG_PTR IatSection = 0;
    ULONG cbIatSection = 0;
    PULONG_PTR pIatEntries = NULL;
    SIZE_T cIatEntries = 0;
    BOOL status = TRUE;

    INF_PRINT("Deobfuscating the import address table...\n");

    pIatSectionHeader = GetPeSectionByName(RemotePeHeader, ".rdata");
    if (!pIatSectionHeader)
    {
        ERR_PRINT("Error: failed to get PE section containing the IAT.\n");
        status = FALSE;
        goto exit;
    }

    IatSection = ImageBase + pIatSectionHeader->VirtualAddress;
    cbIatSection = pIatSectionHeader->Misc.VirtualSize;

    //
    // Verify that the IAT section is inside the target image.
    //
    if (IatSection < ImageBase || ImageBase + cbImageSize < IatSection + cbIatSection)
    {
        ERR_PRINT("Error: IAT section is corrupt.\n");
        ERR_PRINT("    IatSection:      %p - %p\n",
            IatSection,
            IatSection + cbIatSection);
        ERR_PRINT("    Debuggee Image:  %p - %p\n",
            ImageBase,
            ImageBase + cbImageSize);
        status = FALSE;
        goto exit;
    }

    INF_PRINT("Found the remote IAT: %p - %p\n", IatSection, IatSection + cbIatSection);

    status = IdfpGetIatEntries(
        hProcess,
        ImageBase,
        IatSection,
        cbIatSection,
        &pIatEntries,
        &cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to enumerate IAT entries.\n");
        goto exit;
    }

    INF_PRINT("The remote IAT contains %Iu elements.\n", cIatEntries);

    status = IdfpDeobfuscateIatEntries(
        hProcess,
        pIatEntries,
        cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to deobfuscate the remote IAT.\n");
        goto exit;
    }

    status = IdfpPatchImportAddressTable(
        hProcess,
        ImageBase,
        RemotePeHeader,
        IatSection,
        pIatEntries,
        cIatEntries);
    if (!status)
    {
        ERR_PRINT("Error: failed to patch the remote IAT.\n");
        goto exit;
    }

    INF_PRINT("Successfully restored the remote IAT.\n");

exit:
    if (pIatEntries)
    {
        if (!HeapFree(GetProcessHeap(), 0, pIatEntries))
        {
            ERR_PRINT("HeapFree failed: %u\n", GetLastError());
        }
    }

    return status;
}
