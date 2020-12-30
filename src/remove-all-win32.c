/*
 * Finds all .text sections and fixes them up.
 */

#ifdef WIN32

#include <windows.h>
#include <libloaderapi.h>
#include <dbghelp.h>
#include <noseatbelt/noseatbelt.h>

#include "debug.h"

void remove_all_seatbelts() {
    SeatbeltState state;

    init_seatbelt(&state, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    HMODULE pImage = GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS* pHeader = ImageNtHeader(pImage);

    IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*) (pHeader + 1);

    ZyanU8* base_address = (ZyanU8*) pImage;

    for (auto count = 0u; count < pHeader->FileHeader.NumberOfSections; ++count)
    {
        if (memcmp(pSectionHeaders->Name, ".text", 5) == 0)
        {
            ZyanU8* pTextStart = (ZyanU8*) (base_address + pSectionHeaders->VirtualAddress);
            ZyanU8* pTextEnd = (ZyanU8*) (base_address + pSectionHeaders->VirtualAddress + pSectionHeaders->Misc.VirtualSize);

            DWORD oldProtect = 0;

            VirtualProtect(pTextStart, pTextEnd - pTextStart, PAGE_EXECUTE_WRITECOPY, &oldProtect);

            remove_seatbelts(&state, pTextStart, pTextEnd);   
            
            VirtualProtect(pTextStart, pTextEnd - pTextStart, oldProtect, NULL);
        }

        ++pSectionHeaders;
    }

    DEBUG_PRINT(1, "Removed %I64u call trampoline calls.\n", state.call_trampolines);
    DEBUG_PRINT(1, "Removed %I64u return trampoline jumps.\n", state.return_trampolines);
}

#endif