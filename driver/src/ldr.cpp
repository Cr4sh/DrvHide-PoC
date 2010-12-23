#include "stdafx.h"
//--------------------------------------------------------------------------------------
BOOLEAN LdrProcessRelocs(PVOID Image, PVOID NewBase)
{
    PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PIMAGE_BASE_RELOCATION pRelocation = NULL;
    ULONG RelocationSize = 0;        
    ULONGLONG OldBase = 0;

    if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        // 32-bit image
        if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        {
            pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(
                Image,
                pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
            );

            RelocationSize = pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }

        OldBase = pHeaders32->OptionalHeader.ImageBase;
    }        
    else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        // 64-bit image
        PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
            ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

        if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        {
            pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(
                Image,
                pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
            );

            RelocationSize = pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        }

        OldBase = pHeaders64->OptionalHeader.ImageBase;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unkown machine type\n");
        return FALSE;
    }

    if (pRelocation)
    {

#ifdef DBGMSG_LDR

        DbgMsg(__FILE__, __LINE__, "IMAGE_DIRECTORY_ENTRY_BASERELOC: "IFMT"; Size: %d\n", pRelocation, RelocationSize);

#endif

        ULONG Size = 0;
        while (RelocationSize > Size && pRelocation->SizeOfBlock)
        {            
            ULONG Number = (pRelocation->SizeOfBlock - 8) / 2;
            PUSHORT Rel = (PUSHORT)((PUCHAR)pRelocation + 8);            

#ifdef DBGMSG_LDR

            DbgMsg(__FILE__, __LINE__, " VirtualAddress: 0x%.8x; Number of Relocs: %d; Size: %d\n", 
                pRelocation->VirtualAddress, Number, pRelocation->SizeOfBlock
            );

#endif
            for (ULONG i = 0; i < Number; i++)
            {
                if (Rel[i] > 0)
                {
                    USHORT Type = (Rel[i] & 0xF000) >> 12;

                    // check for supporting type
                    if (Type != IMAGE_REL_BASED_HIGHLOW &&
                        Type != IMAGE_REL_BASED_DIR64)
                    {
                        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: Unknown relocation type (%d)\n", Type);
                        return FALSE;
                    }
#ifdef _X86_
                    PUCHAR *Addr = (PUCHAR *)RVATOVA(Image, pRelocation->VirtualAddress + (Rel[i] & 0x0FFF));                                                            
                    *((PULONG)Addr) += (ULONG)((ULONGLONG)NewBase - OldBase);
#elif _AMD64_
                    *(PULONGLONG)(RVATOVA(Image, pRelocation->VirtualAddress + 
                        (Rel[i] & 0x0FFF))) += (ULONGLONG)NewBase - OldBase;
#endif
                }
            }

            pRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocation + pRelocation->SizeOfBlock);
            Size += pRelocation->SizeOfBlock;            
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() WARNING: Relocation directory is not found\n");
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
// EoF
