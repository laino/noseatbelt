#pragma once

#ifdef WIN32
#include <windows.h>
#endif

#include <Zydis/Zydis.h>
#include "dll-helper.h"

/*
 * A region of memory.
 */
typedef struct SeatbeltMemoryRegion_ {
    ZyanU8* start;
    ZyanU8* end;
} SeatbeltMemoryRegion;

/*
 * A list of regions of memory.
 */
typedef struct SeatbeltMemory {
    ZyanUSize num_regions;
    SeatbeltMemoryRegion regions[];
} SeatbeltMemory;

DllExport typedef struct SeatbeltState_ {
    // Decoder
    ZydisDecoder decoder;

    // Pointer to current instruction
    ZyanU8 *current;

    // Pointer to next instruction
    ZyanU8 *next;

    // current memory region start
    ZyanU8 *current_region_start;

    // current memory region end
    ZyanU8 *current_region_end;

    // TODO allow configuring an offse for the instruction pointer
    // if it doesn't match the memory location.
    // ZyanU8 *ioffset;

    // Current instruction
    ZydisDecodedInstruction *instruction;
    ZydisDecodedInstruction _instruction; // TODO: instruction cache?

    // The executable memory with read+write permissions.
    // If not NULL, only the regions listed here will be written to or read from.
    // Must be an ordered list.
    SeatbeltMemory *memory;

#ifdef WIN32
    struct nt_config_ {
        ZyanU8 *cf_check_function;
        ZyanU8 *cf_dispatch_function;
    } nt_config;
#endif

    // Number of call trampoline calls rewritten
    ZyanUSize call_trampolines;

    // Number of return trampolines rewritten
    ZyanUSize return_trampolines;

    // Number of _guard_check_icall calls removed
    ZyanUSize check_icall;

    // Number of _guard_dispatch_icall calls rewritten
    ZyanUSize dispatch_icall;

    // Number of jumps inlined
    // note that this includes jumps to trampolines
    ZyanUSize jumps_inlined;

    // Number of call redirects resolved and inlined
    // note that this includes calls to trampolines
    ZyanUSize call_redirects_resolved;

    // Number of bytes processed
    ZyanUSize bytes_processed;

    // Number of instructions processed
    ZyanUSize instructions_processed;

    // Number of invalid instructions encountered
    ZyanUSize invalid_instructions;
} SeatbeltState;

/*
 * Initializes a SeatbeltState struct.
 */
DllExport void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width);

/*
 * Applies transformations to the given range of instructions
 * in memory.
 */
DllExport void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end);

/*
 * Tries to automatically detect information about the currently
 * running program and apply transformations to it.
 */
DllExport void remove_all_seatbelts_auto();

#ifdef WIN32
/*
 * Applies transformations to a loaded module (DLL, EXE, ...)
 */
DllExport void remove_module_seatbelts(SeatbeltState *state, HMODULE module);
#endif
