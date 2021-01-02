#ifdef WIN32

#include <windows.h>
#include <libloaderapi.h>
#include <dbghelp.h>

#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

#define MAX_REGIONS 1

void remove_module_seatbelts(SeatbeltState *state, HMODULE pImage) {
    SeatbeltMemory* memory, *old_memory;
    SeatbeltMemoryRegion *region;
    int OLD_FLAGS[MAX_REGIONS];
    int i;

    old_memory = state->memory;

    IMAGE_NT_HEADERS* pHeader = ImageNtHeader(pImage);
    ZyanU8* base_address = (ZyanU8*) pHeader->OptionalHeader.ImageBase;

    if (pHeader->OptionalHeader.NumberOfRvaAndSizes >= 10) {
        IMAGE_LOAD_CONFIG_DIRECTORY *load_config = (IMAGE_LOAD_CONFIG_DIRECTORY*) 
            (pHeader->OptionalHeader.DataDirectory[10].VirtualAddress + pHeader->OptionalHeader.ImageBase);

        state->nt_config.cf_check_function =  *((ZyanU8**) load_config->GuardCFCheckFunctionPointer);
        state->nt_config.cf_dispatch_function = *((ZyanU8**) load_config->GuardCFDispatchFunctionPointer);
    }

    memory = malloc(sizeof(SeatbeltMemory) + sizeof(SeatbeltMemoryRegion) * MAX_REGIONS);
    memory->num_regions = 1;
    memory->regions[0].start = base_address;
    memory->regions[0].end = base_address + pHeader->OptionalHeader.SizeOfImage;
    state->memory = memory;

    printf("%p, %p\n", memory->regions[0].start, memory->regions[0].end);
    
    IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*) (pHeader + 1);

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

    state->memory = old_memory;

    free(memory);

    state->nt_config.cf_check_function = NULL;
    state->nt_config.cf_dispatch_function = NULL;
}

#endif
