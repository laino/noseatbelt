#ifdef WIN32

#include <windows.h>
#include <libloaderapi.h>
#include <dbghelp.h>

#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

void remove_module_seatbelts(SeatbeltState *state, HMODULE pImage) {
    IMAGE_NT_HEADERS* pHeader = ImageNtHeader(pImage);

    if (pHeader->OptionalHeader.NumberOfRvaAndSizes >= 10) {
        IMAGE_LOAD_CONFIG_DIRECTORY *load_config = (IMAGE_LOAD_CONFIG_DIRECTORY*) 
            (pHeader->OptionalHeader.DataDirectory[10].VirtualAddress + pHeader->OptionalHeader.ImageBase);

        state->nt_config.cf_check_function =  *((ZyanU8**) load_config->GuardCFCheckFunctionPointer);
        state->nt_config.cf_dispatch_function = *((ZyanU8**) load_config->GuardCFDispatchFunctionPointer);
    }
    
    IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*) (pHeader + 1);

    ZyanU8* base_address = (ZyanU8*) pImage;

    for (ZyanU8 count = 0u; count < pHeader->FileHeader.NumberOfSections; ++count) {
        if (memcmp(pSectionHeaders->Name, ".text", 5) == 0) {
            ZyanU8* pTextStart = (ZyanU8*) (base_address + pSectionHeaders->VirtualAddress);
            ZyanU8* pTextEnd = (ZyanU8*) (base_address + pSectionHeaders->VirtualAddress + pSectionHeaders->Misc.VirtualSize);

            DWORD oldProtect = 0;

            VirtualProtect(pTextStart, pTextEnd - pTextStart, PAGE_EXECUTE_WRITECOPY, &oldProtect);

            remove_seatbelts(state, pTextStart, pTextEnd);

            VirtualProtect(pTextStart, pTextEnd - pTextStart, oldProtect, NULL);
        }

        ++pSectionHeaders;
    }

    state->nt_config.cf_check_function = NULL;
    state->nt_config.cf_dispatch_function = NULL;
}

#endif
