#pragma once

/*
This stuff is extracted from winnt.h header file
*/

#include <ntifs.h>
#define BYTE  unsigned char
#define WORD  unsigned short
#define DWORD unsigned int
//#define ULONGLONG unsigned long long
//#define LONG long
//#define USHORT unsigned short

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;      // Magic number (MZ)
    USHORT e_cblp;       // Bytes on the last page of the file
    USHORT e_cp;         // Pages in the file
    USHORT e_crlc;       // Relocations
    USHORT e_cparhdr;    // Size of the header in paragraphs
    USHORT e_minalloc;   // Minimum extra paragraphs needed
    USHORT e_maxalloc;   // Maximum extra paragraphs needed
    USHORT e_ss;         // Initial (relative) SS value
    USHORT e_sp;         // Initial SP value
    USHORT e_csum;       // Checksum
    USHORT e_ip;         // Initial IP value
    USHORT e_cs;         // Initial (relative) CS value
    USHORT e_lfarlc;     // File address of relocation table
    USHORT e_ovno;       // Overlay number
    USHORT e_res[4];     // Reserved words
    USHORT e_oemid;      // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;    // OEM information; e_oemid specific
    USHORT e_res2[10];   // Reserved words
    LONG   e_lfanew;     // File address of the PE signature
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


#define IMAGE_DOS_SIGNATURE 0x5A4D   // "MZ" in ASCII

#define IMAGE_NT_SIGNATURE  0x00004550 // "PE\0\0" in ASCII



#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

