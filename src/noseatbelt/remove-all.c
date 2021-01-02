#include <stdio.h>
#include <inttypes.h>

#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

void _remove_all_seatbelts(SeatbeltState *state);

void remove_all_seatbelts_auto(SeatbeltState *state) {
    DEBUG_PRINT(1, "--NoSeatbelt-----------------\n\n");

    init_seatbelt(state, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    _remove_all_seatbelts(state);

    DEBUG_PRINT(1, "\n%"PRIu64" bytes processed (instructions: %"PRIu64", invalid: %"PRIu64"):\n", 
        state->bytes_processed, state.instructions_processed, state.invalid_instructions);

    DEBUG_PRINT(1, " %"PRIu64" call trampolines\n", state->call_trampolines);
    DEBUG_PRINT(1, " %"PRIu64" return trampolines\n", state->return_trampolines);
    DEBUG_PRINT(1, " %"PRIu64" calls redirected\n", state->call_redirects_resolved);
    DEBUG_PRINT(1, " %"PRIu64" jumps inlined\n", state->jumps_inlined);

#ifdef WIN32
    DEBUG_PRINT(1, " %"PRIu64" _guard_dispatch_icall calls\n", state->dispatch_icall);
    DEBUG_PRINT(1, " %"PRIu64" _guard_check_icall calls\n", state->check_icall);
#endif

    DEBUG_PRINT(1, "\n--NoSeatbelt-----------------\n\n");
}
