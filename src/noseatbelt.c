#include <stdio.h>
#include <inttypes.h>
#include <noseatbelt/noseatbelt.h>

#include "debug.h"

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

/*
 * Calculates the address of an immediate operand.
 */
static ZyanBool memory_location_from_immediate_operand(ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8** loc) {
    *loc = (op->imm.is_relative ? rip : 0) + (op->imm.is_signed ? op->imm.value.s : op->imm.value.u);

    return 1;
}

/*
 * Attempts to statically calculate the address of a memory operand if possible.
 */
static ZyanBool memory_location_from_memory_operand(ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8**loc) {
    if (op->mem.base == ZYDIS_REGISTER_RIP &&
        op->mem.disp.has_displacement &&
        op->mem.index == ZYDIS_REGISTER_NONE &&
        op->mem.scale == ZYDIS_REGISTER_NONE && (
        op->mem.segment == ZYDIS_REGISTER_ES ||
        op->mem.segment == ZYDIS_REGISTER_CS ||
        op->mem.segment == ZYDIS_REGISTER_SS ||
        op->mem.segment == ZYDIS_REGISTER_DS)) {

        *loc = *(ZyanU8**)(rip + op->mem.disp.value);
        return 1;
    }

    return 0;
}

/*
 * Attempts to statically calculate the address of an operand if possible.
 */
static ZyanBool memory_location_from_operand(ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8**loc) {
    if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return memory_location_from_immediate_operand(op, rip, loc);
    } else if (op->type == ZYDIS_OPERAND_TYPE_MEMORY) {
        return memory_location_from_memory_operand(op, rip, loc);
    }

    return 0;
}

/*
 * Writes a RET instruction.
 */
static ZyanBool write_RET(ZyanU8* start, ZyanU8* end) {
    *(start) = 0xc3;
    start++;

    // Fill rest with NOOP
    while (start < end) {
        *(start) = 0x90;
        start++;
    }

    return 1;
}

/*
 * Writes a CALL instruction to a memory location stored in reg.
 */
static ZyanBool write_CALL(ZyanU8* start, ZyanU8* end, ZydisRegister reg) {
    ZyanU8 reg_code = register_code(reg);

    ZyanU8 ow[3];
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

    /*
     * Compilers may generate code that tests where control
     * returned *to* after call. That's why we put NOOPs
     * at the beginning.
     */
    while (start + len < end) {
        *(start) = 0x90;
        start++;
    }

    ZyanU8 offset = 0;

    while (start + offset < end) {
        assert(offset < len);
        *(start + offset) = ow[offset];
        offset++;
    }

    return 1;
}

enum DECODE_FLAGS {
    DECODE_FLAG_NONE = 0x0,
    DECODE_FLAG_SKIP_NOOP = 0x1,
    DECODE_FLAG_PEEK = 0x2,
};

#define PINFO(state, fmt, ...) \
    DEBUG_PRINT(1, "%p %s: " fmt, state->current, ZydisMnemonicGetString(state->instruction->mnemonic), ##__VA_ARGS__)

#define PVERBOSE(state, fmt, ...) \
    DEBUG_PRINT(2, "%p %s: " fmt, state->current, ZydisMnemonicGetString(state->instruction->mnemonic), ##__VA_ARGS__)

static ZyanBool decode_next(SeatbeltState *state, ZyanU8 **start, ZyanU8 *end, ZyanU8 flags) {
    ZyanU8 status = 1;

    ZyanU8* current = *start;

    do {
        // Make peeking free
        if (current != state->current) {
            status = ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&state->decoder, current, end - current, state->instruction));

            if (!status) {
                return status;
            }

            state->current = current;
            state->next = current + state->instruction->length;

            DEBUG_PRINT(3, "%p %s\n", current, ZydisMnemonicGetString(state->instruction->mnemonic));
        }

        current = state->next;
    } while (flags & DECODE_FLAG_SKIP_NOOP && state->instruction->mnemonic == ZYDIS_MNEMONIC_NOP);

    if ((flags & DECODE_FLAG_PEEK) == 0) {
        *start = current;
    }

    return status;
}

#define DECODE_OP(state, start, end) decode_next(state, &start, end, DECODE_FLAG_SKIP_NOOP)
#define DECODE(state, start, end) decode_next(state, &start, end, DECODE_FLAG_NONE)

#define PEEK_OP(state, start, end) decode_next(state, &start, end, DECODE_FLAG_PEEK & DECODE_FLAG_SKIP_NOOP)
#define PEEK(state, start, end) decode_next(state, &start, end, DECODE_FLAG_PEEK)

#define EXPECT_OP(ins, state, start, end) \
    if (!DECODE_OP(state, start, end) || state->instruction->mnemonic != ZYDIS_MNEMONIC_ ## ins) {\
        PVERBOSE(state, "Expected " #ins "\n");\
        return 0;\
    }

static ZyanBool check_thunk_head(SeatbeltState *state, ZyanU8 **start, ZyanU8 *end) {
    ZyanU8 *pause_address;
    ZyanU8 *call_target;
    ZyanU8 *jmp_target;

    EXPECT_OP(CALL, state, *start, end);

    if (!memory_location_from_operand(&state->instruction->operands[0], *start, &call_target)) {
        PVERBOSE(state, "Couldn't decode CALL target\n");
        return 0;
    }

    EXPECT_OP(PAUSE, state, *start, end);
    pause_address = state->current;

    EXPECT_OP(LFENCE, state, *start, end);
    EXPECT_OP(JMP, state, *start, end);

    if (!memory_location_from_operand(&state->instruction->operands[0], *start, &jmp_target)) {
        PVERBOSE(state, "Couldn't decode JMP target\n");
        return 0;
    }

    if (jmp_target != pause_address) { // Should JMP to PAUSE
        PVERBOSE(state, "Expected JMP to %p\n", pause_address);

        return 0;
    }

    while (PEEK(state, *start, end)) {
        // Call target should point to the next instruction
        if (call_target == *start) {
            return 1;
        }

        if (state->instruction->mnemonic == ZYDIS_MNEMONIC_NOP) {
            *start = state->next;
        } else {
            break;
        }
    }

    PVERBOSE(state, "Expected CALL to point before %p\n", *start);

    return 0;
}

static ZyanBool check_indirect_thunk(TrampolineInformation *info, SeatbeltState *state, ZyanU8 *start) {
    PVERBOSE(state, "Checking for indirect thunk at %p\n", start);

    ZydisDecodedOperand *op0, *op1;

    info->reg = ZYDIS_REGISTER_NONE;

    ZyanU8 *end = start + MAX_TRAMPOLINE_LENGTH;

    if (!check_thunk_head(state, &start, end)) {
        return 0;
    }

    EXPECT_OP(MOV, state, start, end);

    op0 = &state->instruction->operands[0];
    op1 = &state->instruction->operands[1];

    if (op0->type != ZYDIS_OPERAND_TYPE_MEMORY ||
        op0->mem.base != ZYDIS_REGISTER_RSP ||
        op1->type != ZYDIS_OPERAND_TYPE_REGISTER) {

        PVERBOSE(state, "Expected MOV to rsp\n");
        return 0;
    }

    info->reg = op1->reg.value;

    EXPECT_OP(RET, state, start, end);

    PINFO(state, "Indirect thunk found for register %s\n", ZydisRegisterGetString(info->reg));

    return 1;
}

static ZyanBool check_return_thunk(SeatbeltState *state, ZyanU8 *start) {
    PVERBOSE(state, "Checking for return thunk at %p\n", start);

    ZydisDecodedOperand *op0, *op1;

    ZyanU8 *end = start + MAX_TRAMPOLINE_LENGTH;

    if (!check_thunk_head(state, &start, end)) {
        return 0;
    }

    EXPECT_OP(LEA, state, start, end);

    op0 = &state->instruction->operands[0];
    op1 = &state->instruction->operands[1];

    // TODO: displacement will be different on 32bit
    if (op0->type != ZYDIS_OPERAND_TYPE_REGISTER ||
        op0->reg.value != ZYDIS_REGISTER_RSP ||
        op1->type != ZYDIS_OPERAND_TYPE_MEMORY ||
        op1->mem.type != ZYDIS_MEMOP_TYPE_AGEN ||
        !op1->mem.disp.has_displacement ||
        op1->mem.disp.value != 8 ||
        op1->mem.base != ZYDIS_REGISTER_RSP) {

        PVERBOSE(state, "LEA should store rsp+0x8 to rsp.\n");

        return 0;
    }

    EXPECT_OP(RET, state, start, end);

    PINFO(state, "Return thunk found\n");

    return 1;
};

static void handle_call(SeatbeltState *state, ZyanU8 *start) {
    ZyanU8 *target_address;
    ZyanU8 *call_address = state->current;
    ZyanU8 *call_next = state->next;

    if (!memory_location_from_operand(&state->instruction->operands[0], start, &target_address)) {
        return;
    }

    // Could be an inline return thunk
    if (check_return_thunk(state, state->current)) {
        if (write_RET(call_address, call_next)) {
            state->return_trampolines++;
        }
        return;
    }

    TrampolineInformation trampoline_info;

    // TODO Put a limit on following jumps, there could be infinite loops.
    while (PEEK(state, target_address, target_address + MAX_TRAMPOLINE_LENGTH) &&
        state->instruction->mnemonic == ZYDIS_MNEMONIC_JMP) {
        // the call is being redirected somewhere, follow...

        if (!memory_location_from_operand(&state->instruction->operands[0], state->next, &target_address)) {
            break;
        }
    }

    if (!check_indirect_thunk(&trampoline_info, state, target_address)) {
        return;
    }

    if (write_CALL(call_address, call_next, trampoline_info.reg)) {
        state->call_trampolines++;
    }

    return;
}

static void handle_jmp(SeatbeltState *state, ZyanU8 *start) {
    ZydisDecodedOperand *op0 = &state->instruction->operands[0];

    ZyanU8 *jmp_address = state->current;
    ZyanU8 *target_address;

    if (!memory_location_from_operand(op0, start, &target_address)) {
        return;
    }

    if (!check_return_thunk(state, target_address)) {
        return;
    }

    if (write_RET(jmp_address, start)) {
        state->return_trampolines++;
    }

    return;
}

void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width) {
    state->current = 0;
    state->call_trampolines = 0;
    state->return_trampolines = 0;
    state->bytes_processed = 0;
    state->instruction = &state->_instruction;

    ZydisDecoderInit(&state->decoder, machine_mode, address_width);
}

void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end) {
    DEBUG_PRINT(1, "Scanning %p to %p\n", start, end);

    state->bytes_processed += end - start;

    while (DECODE_OP(state, start, end)) {
        switch (state->instruction->mnemonic) {
            case ZYDIS_MNEMONIC_CALL:
                handle_call(state, start);
                break;
            case ZYDIS_MNEMONIC_JMP:
                handle_jmp(state, start);
                break;
            default:
                break;
        }
    }
}
