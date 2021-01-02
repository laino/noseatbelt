#ifdef WIN32

#include <windows.h>
#include <libloaderapi.h>
#include <dbghelp.h>
#include <string.h>

#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

static BOOL _loaded_module_callback(PCSTR moduleName, DWORD64 moduleBase, ULONG moduleSize, SeatbeltState *state) {
    HMODULE moduleImage;

    if (!strnicmp(moduleName, "C:\\WINDOWS", 10)) {
        return 1;
    }

    if (!GetModuleHandleExA(0, moduleName, &moduleImage)) {
        return 1;
    }

    DEBUG_PRINT(1, "> Module %s\n", moduleName);

    remove_module_seatbelts(state, moduleImage);

    FreeLibrary(moduleImage);

    return 1;
}

void _remove_all_seatbelts(SeatbeltState *state) {
    EnumerateLoadedModules(GetCurrentProcess(), _loaded_module_callback, state);
}

#endif
