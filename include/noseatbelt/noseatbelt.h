#pragma once

#ifdef WIN32
#include <windows.h>
#endif

#include <Zydis/Zydis.h>

#ifdef WIN32
#define DllExport   __declspec( dllexport )
#define DllImport   __declspec( dllimport )
#else
#define DllExport /* Only on WIN32 */
#define DllImport /* Only on WIN32 */
#endif

DllExport typedef struct SeatbeltState_ {
    // Decoder
    ZydisDecoder decoder;

    // Pointer to current instruction
    ZyanU8 *current;

    // Pointer to next instruction
    ZyanU8 *next;

    // TODO allow configuring an offse for the instruction pointer
    // if it doesn't match the memory location.
    // ZyanU8 *ioffset;

    // Current instruction
    ZydisDecodedInstruction *instruction;
    ZydisDecodedInstruction _instruction; // TODO: instruction cache?

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

    // Number of jumps inlined, note that this includes
    // jumps to return trampolines
    ZyanUSize jumps_inlined;

    // Number of bytes processed
    ZyanUSize bytes_processed;
} SeatbeltState;

DllExport typedef struct TrampolineInformation_ {
    ZydisRegister reg;
} TrampolineInformation;

DllExport void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width);

DllExport void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end);

DllExport void remove_all_seatbelts_auto();

#ifdef WIN32
DllExport void remove_module_seatbelts(SeatbeltState *state, HMODULE module);
#endif