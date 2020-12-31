#include <stdio.h>
#include <inttypes.h>

#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

#include "remove-all-win32.c"
#include "remove-all-unix.c"

void remove_all_seatbelts_auto() {
    DEBUG_PRINT(1, "--NoSeatbelt-----------------\n\n");

    SeatbeltState state;

    init_seatbelt(&state, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    _remove_all_seatbelts(&state);

    DEBUG_PRINT(1, "\n%"PRIu64" bytes processed:\n", state.bytes_processed);
    DEBUG_PRINT(1, " %"PRIu64" call trampolines\n", state.call_trampolines);
    DEBUG_PRINT(1, " %"PRIu64" return trampolines\n", state.return_trampolines);
    DEBUG_PRINT(1, " %"PRIu64" jumps inlined\n", state.jumps_inlined);
#ifdef WIN32
    DEBUG_PRINT(1, " %"PRIu64" _guard_dispatch_icall calls\n", state.dispatch_icall);
    DEBUG_PRINT(1, " %"PRIu64" _guard_check_icall calls\n", state.check_icall);
#endif

    DEBUG_PRINT(1, "\n--NoSeatbelt-----------------\n\n");
}
