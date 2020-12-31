#define MAX_TRAMPOLINE_LENGTH 100

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

    // Current instruction
    ZydisDecodedInstruction *instruction;
    ZydisDecodedInstruction _instruction; // TODO: instruction cache?

    // Number of indirect thunk calls found and removed
    ZyanUSize call_trampolines;

    // Number of indirect returns found and removed
    ZyanUSize return_trampolines;
} SeatbeltState;

DllExport typedef struct TrampolineInformation_ {
    ZydisRegister reg;
} TrampolineInformation;

DllExport void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width);
DllExport void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end);
DllExport void remove_all_seatbelts();
