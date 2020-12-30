#define MAX_TRAMPOLINE_LENGTH 100

#include <Zydis/Zydis.h>

typedef struct SeatbeltState_ {
    // Decoder
    ZydisDecoder decoder;

    // Pointer to current instruction
    ZyanU8 *current;

    // Current instruction
    ZydisDecodedInstruction *instruction;
    ZydisDecodedInstruction _instruction; // TODO: instruction cache?

    // Number of indirect thunk calls found and removed
    ZyanUSize call_trampolines;

    // Number of indirect returns found and removed
    ZyanUSize return_trampolines;

} SeatbeltState;

typedef struct TrampolineInformation_ {
    ZydisRegister reg;
} TrampolineInformation;

void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width);
void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end);
