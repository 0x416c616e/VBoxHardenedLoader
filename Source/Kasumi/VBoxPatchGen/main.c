/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.20
*
*  DATE:        04 Jan 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define T_PROGRAMTITLE      L"VirtualBox Patch Generator v1.2.0.1901"
#define T_FILEINFAIL        L"\r\nVPG: Error while processing input file"
#define T_FILEOUTFAIL       L"\r\nVPG: Error while processing output file"

#define MAX_HWID_BLOCKS_DEEP   32
#define MAX_PATCH_BLOCKS       256

BINARY_PATCH_BLOCK_INTERNAL *DataBlocks;

/*
* FindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID FindPattern(
    CONST PBYTE Buffer,
    SIZE_T BufferSize,
    CONST PBYTE Pattern,
    SIZE_T PatternSize
)
{
    PBYTE	p = Buffer;

    if (PatternSize == 0)
        return NULL;
    if (BufferSize < PatternSize)
        return NULL;
    BufferSize -= PatternSize;

    do {
        p = memchr(p, Pattern[0], BufferSize - (p - Buffer));
        if (p == NULL)
            break;

        if (memcmp(p, Pattern, PatternSize) == 0)
            return p;

        p++;
    } while (BufferSize - (p - Buffer) > 0);

    return NULL;
}

/*
* SaveTable
*
* Purpose:
*
* Build and save table to output file.
*
*/
BOOL SaveTable(
    _In_ BINARY_PATCH_BLOCK_INTERNAL *PatchBlock,
    _In_ LPWSTR OutputFileName,
    _In_ UINT BlockCount
)
{
    UINT    i;
    BOOL    bResult = FALSE;
    PUCHAR  Table = NULL;
    SIZE_T  TableSize = 0;
    HANDLE  hFile = INVALID_HANDLE_VALUE;
    DWORD   dwEntrySize, ProcessedSize;
    TCHAR   szOutputFileName[MAX_PATH * 2];

    TableSize = BlockCount * sizeof(BINARY_PATCH_BLOCK_INTERNAL);
    Table = (PUCHAR)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, TableSize);
    if (Table) {
        ProcessedSize = 0;
        for (i = 0; i < BlockCount; i++) {
            dwEntrySize = sizeof(ULONG) + sizeof(UCHAR) + (sizeof(UCHAR) * PatchBlock[i].DataLength);
            if (ProcessedSize + dwEntrySize > (DWORD)TableSize)
                break;
            RtlCopyMemory(&Table[ProcessedSize], &PatchBlock[i], dwEntrySize);
            ProcessedSize += dwEntrySize;
        }
        //error converting table, entries are missing
        if (i != BlockCount) {
            RtlFreeHeap(GetProcessHeap(), 0, Table);
            return FALSE;
        }
        RtlSecureZeroMemory(szOutputFileName, sizeof(szOutputFileName));
        GetCurrentDirectory(MAX_PATH, szOutputFileName);
        _strcat(szOutputFileName, OutputFileName);

        hFile = CreateFile(szOutputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, Table, ProcessedSize, &dwEntrySize, NULL);
            CloseHandle(hFile);
            bResult = (dwEntrySize == ProcessedSize);
        }
        RtlFreeHeap(GetProcessHeap(), 0, Table);
    }
    return bResult;
}

/*
* ProcessInputFile
*
* Purpose:
*
* Program entry point.
*
*/
UINT ProcessInputFile(
    _In_ LPWSTR lpszPath
)
{
    UINT                uResult = (UINT)-1;
    BOOL                cond = FALSE;
    ULONG               rlen, c = 0, d = 0;

    HANDLE              fh = NULL, sec = NULL;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;
    NTSTATUS            status;
    PBYTE               DllBase = NULL, Pattern;
    SIZE_T              DllVirtualSize;

    TCHAR               InputFile[MAX_PATH + 1], LogBuffer[MAX_PATH];

    RtlSecureZeroMemory(&usFileName, sizeof(usFileName));

    do {

        rlen = 0;
        RtlSecureZeroMemory(InputFile, sizeof(InputFile));
        GetCommandLineParam(lpszPath, 1, InputFile, MAX_PATH, &rlen);
        if (rlen == 0)
            break;

        if (GetFileAttributes(InputFile) == (DWORD)-1)
            break;

        if (RtlDosPathNameToNtPathName_U(InputFile, &usFileName, NULL, NULL) == FALSE)
            break;

        InitializeObjectAttributes(&attr, &usFileName,
            OBJ_CASE_INSENSITIVE, NULL, NULL);
        RtlSecureZeroMemory(&iosb, sizeof(iosb));

        status = NtCreateFile(&fh, SYNCHRONIZE | FILE_READ_DATA,
            &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status))
            break;

        status = NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, fh);
        if (!NT_SUCCESS(status))
            break;

        DllBase = NULL;
        DllVirtualSize = 0;
        status = NtMapViewOfSection(sec, NtCurrentProcess(), &DllBase,
            0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(status))
            break;

        DataBlocks = (BINARY_PATCH_BLOCK_INTERNAL*)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(BINARY_PATCH_BLOCK_INTERNAL) * MAX_PATCH_BLOCKS);
        if (DataBlocks == NULL)
            break;

        c = 0;

        //locate VBOX patterns
        cuiPrintText(TEXT("\r\nPattern matching: 'VBOX'\r\n"), TRUE);

        //
        // FACP
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)FACP_PATTERN, sizeof(FACP_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(4 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("FACP\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern FACP not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // RSDT
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)RSDT_PATTERN, sizeof(RSDT_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("RSDT\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern RSDT not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // XSDT
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)XSDT_PATTERN, sizeof(XSDT_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("XSDT\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern XSDT not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // APIC
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)APIC_PATTERN, sizeof(APIC_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("APIC\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern APIC not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // HPET
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)HPET_PATTERN, sizeof(HPET_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("HPET\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern HPET not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // MCFG
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)MCFG_PATTERN, sizeof(MCFG_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("MCFG\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern MCFG not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // VBOXCPU
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VBOXCPU_PATTERN, sizeof(VBOXCPU_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(2 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VBOXCPU\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern VBOXCPU not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // VBOX 1.0 CDROM
        //
        /*RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)CDROMVBOX_PATTERN, sizeof(CDROMVBOX_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(12 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VBOXCDROM\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern VBOXCDROM not found"));
        }
        cuiPrintText(LogBuffer, TRUE);   */

        //
        // VBOX generic
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)JUSTVBOX_PATTERN, sizeof(JUSTVBOX_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(3 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(VBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, VBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VBOX\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern VBOX generic not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //locate VirtualBox pattern
        cuiPrintText(TEXT("\r\nPattern matching: 'VirtualBox'\r\n"), TRUE);

        //
        // 'VirtualBox'
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)JUSTVIRTUALBOX_PATTERN, sizeof(JUSTVIRTUALBOX_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VirtualBox\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern VirtualBox not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // 'VirtualBox__'
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VIRTUALBOX2020_PATTERN, sizeof(VIRTUALBOX2020_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VirtualBox__\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern VirtualBox__ not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // 'VirtualBox GIM'
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VIRTUALBOXGIM_PATTERN, sizeof(VIRTUALBOXGIM_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VirtualBox GIM\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tVirtualBox GIM pattern not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // 'VirtualBox VMM'
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)VIRTUALBOXVMM_PATTERN, sizeof(VIRTUALBOXVMM_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(JUSTVIRTUALBOX_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, JUSTVIRTUALBOX_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("VirtualBox VMM\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern VirtualBox VMM not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //locate Configuration pattern
        cuiPrintText(TEXT("\r\nPattern matching: Configuration\r\n"), TRUE);

        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)CFGSTRINGS_PATTERN, sizeof(CFGSTRINGS_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(26 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(CONFIGURATION_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, CONFIGURATION_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("Cfg\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern Configuration not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        //
        // HWID
        //
        cuiPrintText(TEXT("\r\nPattern matching: Hardware ID\r\n"), TRUE);

        //
        // 80EE
        //

        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        d = 0;
        Pattern = DllBase;
        do {
            Pattern = FindPattern(
                (CONST PBYTE)Pattern, DllVirtualSize - (Pattern - DllBase),
                (CONST PBYTE)PCI80EE_PATTERN, sizeof(PCI80EE_PATTERN));
            if (Pattern) {
                DataBlocks[c].VirtualOffset = (ULONG)(1 + Pattern - DllBase);
                DataBlocks[c].DataLength = sizeof(HWID_PATCH_VIDEO_1);
                RtlCopyMemory(DataBlocks[c].Data, HWID_PATCH_VIDEO_1, DataBlocks[c].DataLength);
                RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
                _strcpy(LogBuffer, TEXT("80EE\t\t0x"));
                ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
                cuiPrintText(LogBuffer, TRUE);
                c += 1;
                d += 1;
                if (d > MAX_HWID_BLOCKS_DEEP) {
                    cuiPrintText(TEXT("\r\nVPG: Maximum hwid blocks deep, abort scan.\r\n"), TRUE);
                    break;
                }
            }
            else {
                break;
            }
            Pattern++;
        } while (DllVirtualSize - (Pattern - DllBase) > 0);

        //
        // BEEF
        //

        d = 0;
        Pattern = DllBase;
        do {
            Pattern = FindPattern(
                (CONST PBYTE)Pattern, DllVirtualSize - (Pattern - DllBase),
                (CONST PBYTE)PCIBEEF_PATTERN, sizeof(PCIBEEF_PATTERN));
            if (Pattern) {
                DataBlocks[c].VirtualOffset = (ULONG)(1 + Pattern - DllBase);
                DataBlocks[c].DataLength = sizeof(HWID_PATCH_VIDEO_2);
                RtlCopyMemory(DataBlocks[c].Data, HWID_PATCH_VIDEO_2, DataBlocks[c].DataLength);
                RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
                _strcpy(LogBuffer, TEXT("BEEF\t\t0x"));
                ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
                cuiPrintText(LogBuffer, TRUE);
                c += 1;
                d += 1;
                if (d > MAX_HWID_BLOCKS_DEEP) {
                    cuiPrintText(TEXT("\r\nVPG: Maximum hwid blocks deep, abort scan.\r\n"), TRUE);
                    break;
                }
            }
            else {
                break;
            }
            Pattern++;
        } while (DllVirtualSize - (Pattern - DllBase) > 0);

        //
        // CAFE
        //
        RtlSecureZeroMemory(LogBuffer, sizeof(LogBuffer));
        Pattern = FindPattern(
            (CONST PBYTE)DllBase, DllVirtualSize,
            (CONST PBYTE)PCICAFE_PATTERN, sizeof(PCICAFE_PATTERN));
        if (Pattern) {
            DataBlocks[c].VirtualOffset = (ULONG)(1 + Pattern - DllBase);
            DataBlocks[c].DataLength = sizeof(HWID_PATCH);
            RtlCopyMemory(DataBlocks[c].Data, HWID_PATCH, DataBlocks[c].DataLength);
            _strcpy(LogBuffer, TEXT("CAFE\t\t0x"));
            ultohex((ULONG)DataBlocks[c].VirtualOffset, _strend(LogBuffer));
            c += 1;
        }
        else {
            _strcpy(LogBuffer, TEXT("\tPattern CAFE not found"));
        }
        cuiPrintText(LogBuffer, TRUE);

        if (SaveTable(DataBlocks, TEXT("\\output.bin"), c))
            uResult = 0;
        else
            uResult = (UINT)-2;

    } while (cond);

    if (usFileName.Buffer != NULL) {
        RtlFreeUnicodeString(&usFileName);
    }

    if (DllBase != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), DllBase);

    if (fh != NULL)
        NtClose(fh);

    if (sec != NULL)
        NtClose(sec);

    if (DataBlocks != NULL)
        RtlFreeHeap(GetProcessHeap(), 0, DataBlocks);

    return uResult;
}

/*
* KasumiMain
*
* Purpose:
*
* Program entry point.
*
*/
void KasumiMain(
    VOID
)
{
    BOOL cond = FALSE;
    UINT uResult = 0;

    __security_init_cookie();

    do {

        cuiInitialize(FALSE, NULL);

        SetConsoleTitle(T_PROGRAMTITLE);

        cuiPrintText(T_PROGRAMTITLE, TRUE);

        uResult = ProcessInputFile(GetCommandLine());

        switch (uResult) {

        case (UINT)-2:
            cuiPrintText(T_FILEOUTFAIL, TRUE);

        case (UINT)-1:
            cuiPrintText(TEXT("\r\nInput file not found"), TRUE);
            break;

        case 0: //success
            cuiPrintText(TEXT("\r\nOutput file generated"), TRUE);
            break;

        default:
            cuiPrintText(T_FILEINFAIL, FALSE);
            break;
        }

    } while (cond);

    ExitProcess(0);
}
