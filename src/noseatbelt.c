#include <stdio.h>
#include <inttypes.h>
#include "Zydis/Zydis.h"

#define DEBUG 1
#define MAX_TRAMPOLINE_LENGTH 100

typedef struct SeatbeltState_ {
    // Decoder
    ZydisDecoder decoder;

    // Pointer to current instruction
    ZyanU8 *current;
    
    // Current instruction
    ZydisDecodedInstruction instruction;

    // Number of trampoline calls found and removed
    ZyanUSize trampolines;
} SeatbeltState;

typedef struct TrampolineInformation_ {
    ZydisRegister reg;
} TrampolineInformation;

#define MODRM(mod, regOrOpcode, rm) mod << 6 | regOrOpcode << 3 | rm
static ZyanU8 register_code(ZydisRegister reg) {
    switch(reg) {
        // 16 bit
        case ZYDIS_REGISTER_AX: return 0;
        case ZYDIS_REGISTER_CX: return 1;
        case ZYDIS_REGISTER_DX: return 2;
        case ZYDIS_REGISTER_BX: return 3;
        case ZYDIS_REGISTER_SP: return 4;
        case ZYDIS_REGISTER_BP: return 5;
        case ZYDIS_REGISTER_SI: return 6;
        case ZYDIS_REGISTER_DI: return 7;
        case ZYDIS_REGISTER_R8W: return 8;
        case ZYDIS_REGISTER_R9W: return 9;
        case ZYDIS_REGISTER_R10W: return 10;
        case ZYDIS_REGISTER_R11W: return 11;
        case ZYDIS_REGISTER_R12W: return 12;
        case ZYDIS_REGISTER_R13W: return 13;
        case ZYDIS_REGISTER_R14W: return 14;
        case ZYDIS_REGISTER_R15W: return 15;

        // 32bit
        case ZYDIS_REGISTER_EAX: return 0;
        case ZYDIS_REGISTER_ECX: return 1;
        case ZYDIS_REGISTER_EDX: return 2;
        case ZYDIS_REGISTER_EBX: return 3;
        case ZYDIS_REGISTER_ESP: return 4;
        case ZYDIS_REGISTER_EBP: return 5;
        case ZYDIS_REGISTER_ESI: return 6;
        case ZYDIS_REGISTER_EDI: return 7;
        case ZYDIS_REGISTER_R8D: return 8;
        case ZYDIS_REGISTER_R9D: return 9;
        case ZYDIS_REGISTER_R10D: return 10;
        case ZYDIS_REGISTER_R11D: return 11;
        case ZYDIS_REGISTER_R12D: return 12;
        case ZYDIS_REGISTER_R13D: return 13;
        case ZYDIS_REGISTER_R14D: return 14;
        case ZYDIS_REGISTER_R15D: return 15;

        // 64bit
        case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_RCX: return 1;
        case ZYDIS_REGISTER_RDX: return 2;
        case ZYDIS_REGISTER_RBX: return 3;
        case ZYDIS_REGISTER_RSP: return 4;
        case ZYDIS_REGISTER_RBP: return 5;
        case ZYDIS_REGISTER_RSI: return 6;
        case ZYDIS_REGISTER_RDI: return 7;
        case ZYDIS_REGISTER_R8: return 8;
        case ZYDIS_REGISTER_R9: return 9;
        case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15: return 15;
        default: return 0;
    }
}

static ZyanU8 overwrite_call(ZyanU8* start, ZyanU8* end, ZydisRegister reg) {
    // Rewrite to direct call.

    ZyanU8 reg_code = register_code(reg);

    ZyanU8 ow[4];
    ZyanU8 len;

    if (reg_code < 8) {
        len = 2;
        ow[0] = 0xFF;
        ow[1] = MODRM(3, 2, reg_code);
    } else {
        len = 3;
        ow[0] = 0x41;
        ow[1] = 0xFF;
        ow[2] = MODRM(3, 2, reg_code - 8);
    }

    if (start + len >= end) {
        // Doesn't fit
        return 0;
    }

    // LLVM likes to generate code that tests where 
    // control returned *to* after a call. So
    // we put padding *before* the call.
    while (start + len < end) {
        *(start) = 0x90;
        start++;
    }

    ZyanU8 offset = 0;

    while (start + offset < end) {
        *(start + offset) = ow[offset];
        offset++;
    }

    return 1;
}

static ZyanU8 decode_next(SeatbeltState *state, ZyanU8 **start, ZyanU8 *end) {
    ZyanU8 status;

    do {
        status = ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&state->decoder, *start, end - *start, &state->instruction));

        if (!status) {
            return status;
        }

        if (DEBUG > 2) {
            printf("%p %s\n", *start, ZydisMnemonicGetString(state->instruction.mnemonic));
        }

        state->current = *start;
        *start += state->instruction.length;
    } while (state->instruction.mnemonic == ZYDIS_MNEMONIC_NOP);

    return status;
}

void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width) {
    state->current = 0;
    state->trampolines = 0;

    ZydisDecoderInit(&state->decoder, machine_mode, address_width);
}

static ZyanU8 check_trampoline(TrampolineInformation *info, SeatbeltState *state, ZyanU8 *start) {
    if (DEBUG > 1) {
        printf("! Checking for trampoline at %p\n", start);
    }

    info->reg = ZYDIS_REGISTER_NONE;

    ZydisDecodedInstruction *instruction = &state->instruction;

    ZyanU8 *end = start + MAX_TRAMPOLINE_LENGTH;

    ZyanU8 *call_target;
    ZyanU8 *pause_address;

    // 1. call
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_CALL) {

        if (DEBUG > 1) {
            printf("> Expected CALL\n");
        }

        return 0;
    }
        
    call_target = start + instruction->operands[0].imm.value.s;
 
    // 2. pause
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_PAUSE) {

        if (DEBUG > 1) {
            printf("> Expected PAUSE\n");
        }

        return 0;
    }
    
    pause_address = state->current;
    
    // 3. lfence 
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_LFENCE) {

        if (DEBUG > 1) {
            printf("> Expected LFENCE\n");
        }

        return 0;
    }

    // 4. jmp
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_JMP ||
        instruction->operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
        instruction->operands[0].imm.value.s + start != pause_address) { // Should JMP to PAUSE

        if (DEBUG > 1) {
            printf("> Expected JMP to %p\n", pause_address);
        }

        return 0;
    }

    // 5. mov
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_MOV ||
        instruction->operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
        instruction->operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        instruction->operands[0].mem.base != ZYDIS_REGISTER_RSP) {

        if (DEBUG > 1) {
            printf("> Expected MOV to rsp\n");
        }

        return 0;
    }
    
    // Call target should point here
    if (call_target != state->current) {
        if (DEBUG > 1) {
            printf("> Expected CALL to point to %p\n", start);
        }

        return 0;
    }

    info->reg = instruction->operands[1].reg.value;
    
    // 6. ret
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_RET) {

        if (DEBUG > 1) {
            printf("> Expected RET\n");
        }

        return 0;
    }
                    
    if (DEBUG) {
        printf("! trampoline detected for register %s\n", ZydisRegisterGetString(info->reg));
    }

    return 1;
}


ZyanU8 handle_call(SeatbeltState *state, ZyanU8 *start) {
    ZydisDecodedInstruction *instruction = &state->instruction;
    ZydisDecodedOperand *operand = &instruction->operands[0];
    
    TrampolineInformation trampoline_info;

    ZyanU8 *call_address = state->current;
    ZyanU8 *target_address;

    if (operand->type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return 0;
    }

    target_address = (operand->imm.is_relative ? start : 0) +
        (operand->imm.is_signed ? operand->imm.value.s : operand->imm.value.u);

    if (DEBUG > 2) {
        printf("> Found call to address %p\n", target_address);
    }

    if (!check_trampoline(&trampoline_info, state, target_address)) {
        return 0;
    }


    if (DEBUG) {
        printf("! Rewrote ");
        ZyanU8 offset = 0;
        while ((call_address + offset) < start) {
            printf("%02X ", *(call_address + offset));
            offset++;
        }
        printf("=> ");
    }

    if (overwrite_call(call_address, start, trampoline_info.reg)) {
        state->trampolines++;
    }

    if (DEBUG) {
        ZyanU8 offset = 0;
        while ((call_address + offset) < start) {
            printf("%X ", *(call_address + offset));
            offset++;
        }

        printf("\n");
    }


    return 1;
}

void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end) {
    ZydisDecodedInstruction *instruction = &state->instruction;

    if (DEBUG) {
        printf("! Scanning %p to %p\n", start, end);
    }

    while (decode_next(state, &start, end)) {
        switch (instruction->mnemonic) {
        case ZYDIS_MNEMONIC_CALL: // far
            handle_call(state, start);
            break;
        default:
            break;
        }
    }
}
