#include <stdio.h>
#include <limits.h>
#include <sys/mman.h>
#include <inttypes.h>

#include <noseatbelt/noseatbelt.h>

#include "debug.h"

#include "remove-all-unix.c"
#include "remove-all-win32.c"

void remove_all_seatbelts() {
    DEBUG_PRINT(1, "--NoSeatbelt-----------------\n\n");

    SeatbeltState state;

    init_seatbelt(&state, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    _remove_all_seatbelts(&state);

    DEBUG_PRINT(1, "\n%"PRIu64" bytes processed:\n", state.bytes_processed);
    DEBUG_PRINT(1, " %"PRIu64" call trampolines\n", state.call_trampolines);
    DEBUG_PRINT(1, " %"PRIu64" return trampolines\n", state.return_trampolines);

    DEBUG_PRINT(1, "\n--NoSeatbelt-----------------\n\n");
}
