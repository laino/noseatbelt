#ifdef WIN32

#include <windows.h>
#include <libloaderapi.h>
#include <dbghelp.h>

#include <noseatbelt/noseatbelt.h>

static void _remove_all_seatbelts(SeatbeltState *state) {
    HMODULE pImage = GetModuleHandleA(NULL);

    remove_module_seatbelts(state, pImage);
}

#endif
