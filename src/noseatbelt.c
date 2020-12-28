#include <stdio.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>

#define DEBUG 1
#define MAX_TRAMPOLINE_LENGTH 100

typedef struct SeatbeltState_ {
    // Decoder
    ZydisDecoder decoder;

    // Pointer to current instruction
    ZyanU8* current;
    
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

static ZyanU8 decode_next(SeatbeltState* state, ZyanU8** start, ZyanU8* end) {
    ZyanStatus status = ZydisDecoderDecodeBuffer(&state->decoder, *start, end - *start, &state->instruction);

    if (DEBUG) {
        printf("%p %s\n", *start, ZydisMnemonicGetString(state->instruction.mnemonic));
    }

    state->current = *start;
    *start += state->instruction.length;

    return ZYAN_SUCCESS(status);
}

void init_seatbelt(SeatbeltState* state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width) {
    state->current = 0;
    state->trampolines = 0;

    ZydisDecoderInit(&state->decoder, machine_mode, address_width);
}

static ZyanU8 check_trampoline(TrampolineInformation* info, SeatbeltState* state, ZyanU8* start) {
    if (DEBUG) {
        printf("! Checking for trampoline at %p\n", start);
    }

    info->reg = ZYDIS_REGISTER_NONE;

    ZydisDecodedInstruction* instruction = &state->instruction;

    ZyanU8* end = start + MAX_TRAMPOLINE_LENGTH;

    ZyanU8* call_target;
    ZyanU8* pause_address;

    // 1. call
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_CALL) {

        if (DEBUG) {
            printf("> Expected CALL\n");
        }

        return 0;
    }
        
    call_target = start + instruction->operands[0].imm.value.s;
 
    // 2. pause
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_PAUSE) {

        if (DEBUG) {
            printf("> Expected PAUSE\n");
        }

        return 0;
    }
    
    pause_address = state->current;
    
    // 3. lfence 
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_LFENCE) {

        if (DEBUG) {
            printf("> Expected LFENCE\n");
        }

        return 0;
    }

    // 4. jmp
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_JMP ||
        instruction->operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
        instruction->operands[0].imm.value.s + start != pause_address) { // Should JMP to PAUSE

        if (DEBUG) {
            printf("> Expected JMP to %p\n", pause_address);
        }

        return 0;
    }

    // Call target should point here
    if (call_target != start) {
        if (DEBUG) {
            printf("> Expected CALL to point to %p\n", start);
        }

        return 0;
    }
    
    // 5. mov
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_MOV ||
        instruction->operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
        instruction->operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        instruction->operands[0].mem.base != ZYDIS_REGISTER_RSP) {

        if (DEBUG) {
            printf("> Expected MOV to rsp\n");
        }

        return 0;
    }

    info->reg = instruction->operands[1].reg.value;
    
    // 6. ret
    if (!decode_next(state, &start, end) ||
        instruction->mnemonic != ZYDIS_MNEMONIC_RET) {

        if (DEBUG) {
            printf("> Expected RET\n");
        }

        return 0;
    }
                    
    if (DEBUG) {
        printf("! trampoline detected for register %s\n", ZydisRegisterGetString(info->reg));
    }

    return 1;
}


ZyanU8 handle_call(SeatbeltState* state, ZyanU8* start) {
    ZydisDecodedInstruction* instruction = &state->instruction;
    ZydisDecodedOperand* operand = &instruction->operands[0];
    
    TrampolineInformation trampoline_info;

    ZyanU8* call_address = state->current;
    ZyanU8* target_address;

    if (operand->type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return 0;
    }

    target_address = (operand->imm.is_relative ? start : 0) +
        (operand->imm.is_signed ? operand->imm.value.s : operand->imm.value.u);

    if (DEBUG) {
        printf("> Found call to address %p\n", target_address);
    }

    if (!check_trampoline(&trampoline_info, state, target_address)) {
        return 0;
    }

    // Rewrite to 'direct' call
    *call_address = 0xFF;
    call_address++;
    *call_address = MODRM(3, 2, register_code(trampoline_info.reg));
    call_address++;

    // Fill with NOOPs if we the old instruction was wider
    while (call_address < start) {
        *call_address = 0x90;
        call_address++;
    }

    if (DEBUG) {
        printf("! Rewrote call at address %p\n", call_address);
    }

    state->trampolines++;

    return 1;
}

void remove_seatbelts(SeatbeltState* state, ZyanU8* start, ZyanU8* end) {
    ZydisDecodedInstruction* instruction = &state->instruction;

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

void test_target() {
    printf("test_target() called!\n");
}

void test() {
 	void (*what)() = test_target;
	what();
}

int main() {
    SeatbeltState state;

    init_seatbelt(&state, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    ZyanU8* start = (ZyanU8*) test;
    ZyanU8* end = (ZyanU8*) main;

    // Make memory writable
    ZyanU8* page_start = (ZyanU8*) ((ZyanU64) start >> 12 << 12);
    ZyanU8* page_end = (ZyanU8*) ((ZyanU64) end >> 12 << 12) + 0x00001000;
    mprotect(page_start, page_end - page_start, PROT_READ | PROT_WRITE| PROT_EXEC);

    remove_seatbelts(&state, start, end);

    test();
}
