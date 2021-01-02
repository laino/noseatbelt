#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

// Debug helpers
#define PINFO(state, fmt, ...) \
    DEBUG_PRINT(1, "%p %s: " fmt, state->current, ZydisMnemonicGetString(state->instruction->mnemonic), ##__VA_ARGS__)
#define PVERBOSE(state, fmt, ...) \
    DEBUG_PRINT(2, "%p %s: " fmt, state->current, ZydisMnemonicGetString(state->instruction->mnemonic), ##__VA_ARGS__)
#define WINFO(start, fmt, ...) \
    DEBUG_PRINT(1, "WRITE %p: " fmt, start, ##__VA_ARGS__)

/*
 * Used for computing MAX_DECODE_INSTRUCTION_LENGTH.
 *
 * Since decode_next is able to skip NOPs, we pad the value
 * with this.
 */
#define MAX_DECODE_NOOP 30

/*
 * Maximum length an instruction can have in bytes,
 * for purposes of computing an upper bound of bytes
 * to consider in decode_next.
 */
#define MAX_DECODE_INSTRUCTION_LENGTH 15 + MAX_DECODE_NOOP

/*
 * How far to recursively resolve jumps or calls.
 */
#define MAX_JUMP_DEPTH 3

/*
 * Computes a ModR/M byte.
 */
#define MODRM(mod, regOrOpcode, rm) mod << 6 | regOrOpcode << 3 | rm

/*
 * Zydis register to register code (number).
 */
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
 * Call this before accessing memory.
 *
 * Checks whether the memory is within the permitted regions
 * and updates state->current_region_start and state->current_region_end
 * with the dimensions of the region *addr resides in.
 *
 * Automatically grows current_region_start and current_region_end to
 * encompass adjacent regions.
 */
static ZyanBool enter_region(SeatbeltState *state, ZyanU8 *addr) {
    ZyanUSize i;
    SeatbeltMemoryRegion *region;
    SeatbeltMemory *memory;
    ZyanU8 *start, *end;

    if (state->current_region_start <= addr && state->current_region_end > addr) {
        return 1;
    }

    if (state->memory == NULL) {
        state->current_region_start = 0;
        state->current_region_end = ((ZyanU8*) NULL) - 1;

        return 1;
    }

    start = 0;
    end = 0;

    memory = state->memory;

    for (i = 0; i < memory->num_regions; i++) {
        region = &memory->regions[i];

        if (end == region->start) {
            end = region->end;
        } else if (start <= addr && end > addr) {
            goto success;
        } else {
            start = region->start;
            end = region->end;
        }
    }

    if (start <= addr && end > addr) {
        goto success;
    }

    return 0;

success:
    state->current_region_start = start;
    state->current_region_end = end;

    return 1;
};

/*
 * Calculates the address of an immediate operand.
 */
static ZyanBool memory_location_from_immediate_operand(ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8** loc) {
    *loc = (op->imm.is_relative ? rip : 0) + (op->imm.is_signed ? op->imm.value.s : op->imm.value.u);

    return 1;
}

/*
 * Attempts to statically calculate the address of a memory operand.
 *
 * Memory operands are calculated using a value stored in memory.
 * It is generally unsafe to use these for making predictions
 * about control flow because they may change.
 */
static ZyanBool memory_location_from_memory_operand(SeatbeltState *state, ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8**loc) {
    if (op->mem.base == ZYDIS_REGISTER_RIP &&
        op->mem.disp.has_displacement &&
        op->mem.index == ZYDIS_REGISTER_NONE &&
        op->mem.scale == ZYDIS_REGISTER_NONE && (
        op->mem.segment == ZYDIS_REGISTER_ES ||
        op->mem.segment == ZYDIS_REGISTER_CS ||
        op->mem.segment == ZYDIS_REGISTER_SS ||
        op->mem.segment == ZYDIS_REGISTER_DS)) {

        ZyanU8 *ptr = rip + op->mem.disp.value;

        if (!enter_region(state, ptr) || state->current_region_end <= ptr + sizeof(ZyanU8*)) {
            return 0;
        }

        *loc = *((ZyanU8**) ptr);

        return 1;
    }

    return 0;
}

/*
 * Whether the given operand is an indirect operand.
 *
 * An indirect operand is any operand whose computed value
 * depends on bytes stored in a memory location.
 */
#define IS_INDIRECT_OPERAND(op) (op->type == ZYDIS_OPERAND_TYPE_MEMORY)

/*
 * Computes a memory location from an indirect operand.
 */
static inline ZyanBool memory_location_from_indirect_operand(SeatbeltState *state, ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8**loc) {
    if (op->type == ZYDIS_OPERAND_TYPE_MEMORY) {
        return memory_location_from_memory_operand(state, op, rip, loc);
    }

    return 0;
}

/*
 * Computes a memory location from a direct operand.
 */
static inline ZyanBool memory_location_from_direct_operand(SeatbeltState *state, ZydisDecodedOperand *op, ZyanU8* rip, ZyanU8**loc) {
    if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return memory_location_from_immediate_operand(op, rip, loc);
    }

    return 0;
}

static ZyanU8 NOOP_TABLE[9][9] = {
    {0x90},
    {0x66, 0x90},
    {0x0F, 0x1F, 0x00},
    {0x0F, 0x1F, 0x40, 0x00},
    {0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
    {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
    {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
};

/*
 * Fills *start to *end with NOPs.
 */
static void write_NOP(ZyanU8* start, ZyanU8* end) {
    ZyanU8 len;

    while (1) {
        len = end - start;

        if (len <= 0) {
            return;
        }

        if (len > 10) {
            len = 9;
        }

        WINFO(start, "NOP (length %"PRIu64")\n", len);

        memcpy(start, NOOP_TABLE[len - 1], len);

        start += len;
    }
}

/*
 * Writes a RET instruction.
 */
static ZyanBool write_RET(ZyanU8* start, ZyanU8* end) {
    WINFO(start, "RET\n");

    *start = 0xc3;

    // Fill rest with NOOP
    write_NOP(start + 1, end);

    return 1;
}

/*
 * Inlines instructions by copying them.
 */
static ZyanBool write_inline(ZyanU8* dst, ZyanU8* src, ZyanU8 src_len, ZyanU8 dst_len) {
    if (src_len > dst_len) {
        // too long to inline
        return 0;
    }

    WINFO(dst, "inlining from %p (length %u/%u)\n", src, src_len, dst_len);

    memcpy(dst, src, src_len);

    // Fill rest with NOOP
    write_NOP(dst + src_len, dst + dst_len);

    return 1;
}

/*
 * Writes a JMP instruction to a target address.
 */
static ZyanBool write_JMP(ZyanU8* start, ZyanU8* end, ZyanU8* target) {
    ZyanU8 ow[5];
    ZyanU8 len;

    ZyanI64 offset;

    offset = target - start - 2;
    if (offset >= -0x7F && offset <= 0x7F) {
        // Fits in 8 bit offset
        len = 2;
        ow[0] = 0xEB;
        ow[1] = (ZyanI8) offset;

        goto encode;
    }

    offset = target - start - 5;
    if (offset >= -0x7FFFFFFF && offset <= 0x7FFFFFFF) {
        // Fits in 32 bit offset
        // 32COMPAT: On 32 bit this is rel16
        len = 5;
        ow[0] = 0xE9;

        *((ZyanI32*) (ow + 1)) = (ZyanI32) offset;

        goto encode;
    }

    // Can't encode
    return 0;
encode:
    if (start + len > end) {
        // Doesn't fit in dst
        return 0;
    }

    WINFO(start, "JMP to %p (length %u)\n", target, len);

    memcpy(start, ow, len);

    // Fill rest with NOOP
    write_NOP(start + len, end);

    return 1;
}

/*
 * Writes a CALL instruction to a target address.
 */
static ZyanBool write_CALL(ZyanU8* start, ZyanU8* end, ZyanU8* target) {
    if (start + 5 > end) {
        // Doesn't fit in dst
        return 0;
    }

    ZyanU8 ow[5];

    ZyanI64 offset = target - end;

    if (offset < -0x7FFFFFFF || offset > 0x7FFFFFFF) {
        return 0;
    }

    ow[0] = 0xE8;

    *((ZyanI32*) (ow + 1)) = (ZyanI32) offset;

    /*
    * Compilers may generate code that tests where control
    * returned *to* after CALL. That's why we put NOOPs
    * at the beginning.
    */
    write_NOP(start, end - 5);

    WINFO(start, "CALL to %p (length 5)\n", target);

    memcpy(end - 5, ow, 5);

    return 1;
}

/*
 * Writes a CALL or JMP instruction to a memory location stored in a register.
 */
static ZyanBool write_CALL_or_JMP_register(ZyanU8* start, ZyanU8* end, ZydisRegister reg, ZyanU8 opcode) {
    // TODO I don't think registers smaller than 64 bit are supported correctly
    ZyanU8 reg_code = register_code(reg);

    ZyanU8 ow[3];
    ZyanU8 len;

    if (reg_code < 8) {
        len = 2;
        ow[0] = 0xFF;
        ow[1] = MODRM(3, opcode, reg_code);
    } else {
        len = 3;
        ow[0] = 0x41;
        ow[1] = 0xFF;
        ow[2] = MODRM(3, opcode, reg_code - 8);
    }

    if (start + len > end) {
        // Doesn't fit
        return 0;
    }

    if (opcode < 4) {
        /*
        * Compilers may generate code that tests where control
        * returned *to* after CALL. That's why we put NOOPs
        * at the beginning.
        */

        write_NOP(start, end - len);
        start = end - len;
    } else {
        write_NOP(start + len, end);
    }

    WINFO(start, "%s to pointer in register %s (length %u)\n", opcode < 4 ? "CALL" : "JMP", ZydisRegisterGetString(reg), len);

    memcpy(start, ow, len);

    return 1;
}

/*
 * Writes a JMP instruction to a memory location stored in a register.
 */
static ZyanBool write_JMP_register(ZyanU8* start, ZyanU8* end, ZydisRegister reg) {
    return write_CALL_or_JMP_register(start, end, reg, 4);
}

/*
 * Writes a CALL instruction to a memory location stored in a register.
 */
static ZyanBool write_CALL_register(ZyanU8* start, ZyanU8* end, ZydisRegister reg) {
    return write_CALL_or_JMP_register(start, end, reg, 2);
}

/*
 * Flags passed to decode_next.
 */
enum DECODE_FLAGS {
    DECODE_FLAG_NONE = 0x0,

    /* Automatically skip NOPs */
    DECODE_FLAG_SKIP_NOOP = 0x1
};

/*
 * Decodes the next instruction at *start, stops at *end.
 *
 * The instruction information will be written to state->instruction.
 *
 * Also updates state->current and state->next.
 */
static ZyanStatus decode_next(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end, ZyanU8 flags) {
    ZyanStatus status = ZYAN_STATUS_SUCCESS;

    ZydisDecodedInstruction* instruction = state->instruction;

    if (!enter_region(state, start)) {
        return ZYAN_STATUS_OUT_OF_RANGE;
    }

    if (end > state->current_region_end) {
        end = state->current_region_end;
    }

    do {
        // Make peeking free
        if (start != state->current) {
            status = ZydisDecoderDecodeBuffer(&state->decoder, start, end - start, instruction);

            if (ZYAN_FAILED(status)) {
                return status;
            }

            state->current = start;
            state->next = start + instruction->length;
        }

        #if !defined(NDEBUG) && NOSEATBELT_DEBUG_LEVEL > 2
        char str[100];
        if (ZydisFormatterFormatInstruction(&state->formatter, state->instruction, str, 100, (ZyanU64) start)) {
            DEBUG_PRINT(3, "%p %s\n", start, str);
        }
        #endif

        start = state->next;
    } while (flags & DECODE_FLAG_SKIP_NOOP && instruction->mnemonic == ZYDIS_MNEMONIC_NOP);

    return status;
}

/*
 * Instruction at this address was changed, invalidate any cache
 */
static ZyanBool invalidate(SeatbeltState *state, ZyanU8 *address) {
    if (address == state->current) {
        state->current = ((ZyanU8*) 0) - 1;
        return 1;
    }

    return 0;
}

// Shorthands
#define INVALIDATE(state, start) invalidate(state, start)
#define DECODE_OP(state, start, end) ZYAN_SUCCESS(decode_next(state, start, end, DECODE_FLAG_SKIP_NOOP))
#define DECODE(state, start, end) ZYAN_SUCCESS(decode_next(state, start, end, DECODE_FLAG_NONE))

// Helper
#define EXPECT_OP(ins, state, start, end) \
    if (!DECODE_OP(state, start, end) || state->instruction->mnemonic != ZYDIS_MNEMONIC_ ## ins) {\
        PVERBOSE(state, "Expected " #ins "\n");\
        return 0;\
    }

typedef struct TrampolineInformation_ {
    ZydisRegister reg;
} TrampolineInformation;

/*
 * Checks whether the instructions at *start are an indirect thunk (retpoline).
 *
 * It does *not* check for a 'valid' thunk header (CALL, LFENCE, PAUSE, JMP),
 * but instead only whether the 'body' matches that of an indirect thunk (MOV, RET).
 */
static ZyanBool check_indirect_thunk(SeatbeltState *state, ZyanU8 *start, TrampolineInformation *info) {
    PVERBOSE(state, "Checking for indirect thunk at %p\n", start);

    ZydisDecodedOperand *op0, *op1;

    info->reg = ZYDIS_REGISTER_NONE;

    EXPECT_OP(MOV, state, start, start + MAX_DECODE_INSTRUCTION_LENGTH);

    op0 = &state->instruction->operands[0];
    op1 = &state->instruction->operands[1];

    if (op0->type != ZYDIS_OPERAND_TYPE_MEMORY ||
        op0->mem.base != ZYDIS_REGISTER_RSP ||
        op1->type != ZYDIS_OPERAND_TYPE_REGISTER) {

        PVERBOSE(state, "Expected MOV to rsp\n");
        return 0;
    }

    info->reg = op1->reg.value;

    EXPECT_OP(RET, state, state->next, state->next + MAX_DECODE_INSTRUCTION_LENGTH);

    PVERBOSE(state, "Indirect thunk found for register %s\n", ZydisRegisterGetString(info->reg));

    return 1;
}

/*
 * Checks whether the instructions at *start are a return thunk (retpoline).
 *
 * It does *not* check for a 'valid' thunk header (CALL, LFENCE, PAUSE, JMP),
 * but instead only whether the 'body' matches that of a return thunk (LEA, RET).
 */
static ZyanBool check_return_thunk(SeatbeltState *state, ZyanU8 *start) {
    PVERBOSE(state, "Checking for return thunk at %p\n", start);

    ZydisDecodedOperand *op0, *op1;

    EXPECT_OP(LEA, state, start, start + MAX_DECODE_INSTRUCTION_LENGTH);

    op0 = &state->instruction->operands[0];
    op1 = &state->instruction->operands[1];

    // 32COMPAT: displacement will be different on 32bit
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

    EXPECT_OP(RET, state, state->next, state->next + MAX_DECODE_INSTRUCTION_LENGTH);

    PVERBOSE(state, "Return thunk found\n");

    return 1;
};

/*
 * Flags with information about how the current
 * instructions was rewritten.
 */
typedef enum REWRITE_FLAGS_{
    REWRITE_FLAG_NONE = 0x0,
    REWRITE_FLAG_REWRITE_RET = 0x1,
    REWRITE_FLAG_REWRITE_CALL = 0x2,
    REWRITE_FLAG_REWRITE_JMP = 0x4,
    REWRITE_FLAG_REWRITE_INLINE = 0x8,
} REWRITE_FLAGS;

static REWRITE_FLAGS handle_instruction(SeatbeltState *state, ZyanU8 jump_depth);

/*
 * Handles a CALL instruction and returns status other than 0 if it was rewritten.
 */
static ZyanBool handle_call(SeatbeltState *state, ZyanU8 jump_depth) {
    TrampolineInformation trampoline_info;

    ZyanU8 *target_address;

    ZyanU8 *call_address = state->current;
    ZyanU8 *call_next = state->next;

    ZydisDecodedOperand *op0 = &state->instruction->operands[0];

    if (!memory_location_from_direct_operand(state, op0, call_next, &target_address)) {
        // indirect operands will cause a memory location to be read
        // when the instruction is executed, it's generallly not safe to do much here

#ifdef WIN32
        if (!memory_location_from_indirect_operand(state, op0, call_next, &target_address)) {
            return REWRITE_FLAG_NONE;
        }
    }
    
    if (target_address && target_address == state->nt_config.cf_dispatch_function) {
        if (!write_CALL_register(call_address, call_next, ZYDIS_REGISTER_RAX)) {
            return REWRITE_FLAG_NONE;
        }

        INVALIDATE(state, call_address);

        state->dispatch_icall++;

        return REWRITE_FLAG_REWRITE_CALL;
    }

    // CALL to _guard_check_icall
    if (target_address && target_address == state->nt_config.cf_check_function) {
        write_NOP(call_address, call_next);

        INVALIDATE(state, call_address);

        state->check_icall++;

        return REWRITE_FLAG_REWRITE_CALL;
    }

    if (IS_INDIRECT_OPERAND(op0)) {
#endif
        return REWRITE_FLAG_NONE;
    }

    /*
     * This CALL points to an indirect thunk body and thus is likely
     * the first instruction of the whole thunk.
     *
     * We 'defuse' the retpoline by rewriting it a JMP instruction
     * that directly goes to the address in the appropriate register.
     *
     * When we parse CALLs and JMPs to this CALL, we will see this JMP
     * instruction and inline it.
     */
    if (check_indirect_thunk(state, target_address, &trampoline_info)) {
        if (!write_JMP_register(call_address, call_next, trampoline_info.reg)) {
            return REWRITE_FLAG_NONE;
        }

        INVALIDATE(state, call_address);

        state->call_trampolines++;

        return REWRITE_FLAG_REWRITE_JMP;
    }

    if (!DECODE_OP(state, target_address, target_address + MAX_DECODE_INSTRUCTION_LENGTH)) {
        return REWRITE_FLAG_NONE;
    }

    // Make sure any transformations, such as defusing indirect thunks,
    // are already applied to target_address.
    handle_instruction(state, jump_depth + 1);

    if (!DECODE_OP(state, target_address, target_address + MAX_DECODE_INSTRUCTION_LENGTH)) {
        return REWRITE_FLAG_NONE;
    }

    // CALL redirect by a JMP. Could be a defused indirect thunk, for example.
    if (state->instruction->mnemonic == ZYDIS_MNEMONIC_JMP) {
        op0 = &state->instruction->operands[0];

        if (op0->type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (!write_CALL_register(call_address, call_next, op0->reg.value)) {
                return REWRITE_FLAG_NONE;
            }

            state->call_redirects_resolved++;

            INVALIDATE(state, call_address);

            return REWRITE_FLAG_REWRITE_CALL;
        }

        if (!memory_location_from_direct_operand(state, op0, state->next, &target_address)) {
            return REWRITE_FLAG_NONE;
        }

        // address needs to be adjusted
        if (!write_CALL(call_address, call_next, target_address)) {
            return REWRITE_FLAG_NONE;
        }

        INVALIDATE(state, call_address);

        state->call_redirects_resolved++;

        return REWRITE_FLAG_REWRITE_CALL;
    }

    // (inline) return thunks start with a CALL.
    if (check_return_thunk(state, target_address)) {
        if (write_RET(call_address, call_next)) {
            INVALIDATE(state, call_address);

            state->return_trampolines++;

            return REWRITE_FLAG_REWRITE_RET;
        }

        return REWRITE_FLAG_NONE;
    }

    return REWRITE_FLAG_NONE;
}

/*
 * Handles a JMP instruction and returns status other than 0 if it was rewritten.
 */
static REWRITE_FLAGS handle_jmp(SeatbeltState *state, ZyanU8 jump_depth) {
    ZyanU8 *target_address;

    ZydisDecodedOperand *op0 = &state->instruction->operands[0];

    ZyanU8 *jmp_address = state->current;
    ZyanU8 *jmp_next = state->next;

    if (!memory_location_from_direct_operand(state, op0, jmp_next, &target_address)) {
        // indirect operands will cause a memory location to be read
        // when the instruction is executed, it's generallly not safe to do much here

#ifdef WIN32
        if (!memory_location_from_indirect_operand(state, op0, jmp_next, &target_address)) {
            return REWRITE_FLAG_NONE;
        }
    }

    // JMP to _guard_dispatch_icall
    if (target_address && target_address == state->nt_config.cf_dispatch_function) {
        if (!write_JMP_register(jmp_address, jmp_next, ZYDIS_REGISTER_RAX)) {
            return REWRITE_FLAG_NONE;
        }

        INVALIDATE(state, jmp_address);

        state->dispatch_icall++;

        return REWRITE_FLAG_REWRITE_JMP;
    }

    // JMP to _guard_check_icall
    if (target_address && target_address == state->nt_config.cf_check_function) {
        if (!write_RET(jmp_address, jmp_next)) {
            return REWRITE_FLAG_NONE;
        }

        INVALIDATE(state, jmp_address);

        state->check_icall++;

        return REWRITE_FLAG_REWRITE_RET;
    }

    if (IS_INDIRECT_OPERAND(op0)) {
#endif
        return REWRITE_FLAG_NONE;
    }

    if (!DECODE_OP(state, target_address, target_address + MAX_DECODE_INSTRUCTION_LENGTH)) {
        return REWRITE_FLAG_NONE;
    }

    // Make sure any transformations, such as defusing indirect thunks,
    // are already applied to target_address.
    handle_instruction(state, jump_depth + 1);

    if (!DECODE_OP(state, target_address, target_address + MAX_DECODE_INSTRUCTION_LENGTH)) {
        return REWRITE_FLAG_NONE;
    }

    // A RET can be trivially inlined. Could be a defused return thunk.
    if (state->instruction->mnemonic == ZYDIS_MNEMONIC_RET) {
        if (!write_inline(jmp_address, target_address, state->instruction->length, jmp_next - jmp_address)) {
            return REWRITE_FLAG_NONE;
        }

        INVALIDATE(state, jmp_address);

        state->jumps_inlined++;

        return REWRITE_FLAG_REWRITE_INLINE;
    }

    // JMP to a JMP, try to resolve it statically.
    if (state->instruction->mnemonic == ZYDIS_MNEMONIC_JMP) {
        op0 = &state->instruction->operands[0];

        if (op0->type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (!write_JMP_register(jmp_address, jmp_next, op0->reg.value)) {
                return REWRITE_FLAG_NONE;
            }

            state->jumps_inlined++;

            INVALIDATE(state, jmp_address);

            return REWRITE_FLAG_REWRITE_JMP;
        }

        if (!memory_location_from_direct_operand(state, op0, state->next, &target_address)) {
            return REWRITE_FLAG_NONE;
        }

        // We need to adjust the target address
        if (!write_JMP(jmp_address, jmp_next, target_address)) {
            return REWRITE_FLAG_NONE;
        }

        state->jumps_inlined++;

        INVALIDATE(state, jmp_address);

        return REWRITE_FLAG_REWRITE_JMP;
    }

    return REWRITE_FLAG_NONE;
}

/*
 * Applies transformations to the current instruction.
 */
static REWRITE_FLAGS handle_instruction(SeatbeltState *state, ZyanU8 jump_depth) {
    if (jump_depth >= MAX_JUMP_DEPTH) {
        return REWRITE_FLAG_NONE;
    }

    switch (state->instruction->mnemonic) {
        case ZYDIS_MNEMONIC_CALL:
            return handle_call(state, jump_depth);
        case ZYDIS_MNEMONIC_JMP:
            return handle_jmp(state, jump_depth);
        default:
            return REWRITE_FLAG_NONE;
    }
}

void init_seatbelt(SeatbeltState *state, ZydisMachineMode machine_mode, ZydisAddressWidth address_width) {
    ZydisDecoderInit(&state->decoder, machine_mode, address_width);

#ifndef NDEBUG
    ZydisFormatterInit(&state->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
#endif

    state->instruction = &state->_instruction;

    state->current = 0;
    state->next = 0;

    state->memory = NULL;
    state->current_region_start = 0;
    state->current_region_end = 0;

    state->call_trampolines = 0;
    state->return_trampolines = 0;
    state->dispatch_icall = 0;
    state->check_icall = 0;
    state->jumps_inlined = 0;
    state->call_redirects_resolved = 0;
    state->bytes_processed = 0;
    state->instructions_processed = 0;
    state->invalid_instructions = 0;

#ifdef WIN32
    state->nt_config.cf_check_function = NULL;
    state->nt_config.cf_dispatch_function = NULL;
#endif
}

void remove_seatbelts(SeatbeltState *state, ZyanU8 *start, ZyanU8 *end) {
    DEBUG_PRINT(1, "Scanning %p to %p\n", start, end);

    state->bytes_processed += end - start;

    ZyanStatus status;

    while (start < end) {
        status = decode_next(state, start, end, DECODE_FLAG_NONE);

        if (ZYAN_FAILED(status)) {
            state->invalid_instructions++;
            start++;
            continue;
        }

        start = state->next;

        state->instructions_processed++;

        handle_instruction(state, 0);
    }

    state->current = 0;
    state->next = 0;
    state->current_region_start = 0;
    state->current_region_end = 0;
}

#if DISABLED_CODE
// Disabled. Could be used to implement "safe" mode later that does more validations.
/*
 * Checks whether there is a thunk head at start.
 * If yes, stores a pointer to the body in *thunk_body.
 */
static ZyanBool check_thunk_head(SeatbeltState *state, ZyanU8 *start, ZyanU8 **thunk_body) {
    ZyanU8 *pause_address;
    ZyanU8 *call_target;
    ZyanU8 *jmp_target;

    ZyanU8 *end = start + MAX_THUNK_HEAD_LENGTH;

    EXPECT_OP(CALL, state, start, end);

    if (!memory_location_from_operand(state, &state->instruction->operands[0], state->next, &call_target)) {
        PVERBOSE(state, "Couldn't decode CALL target\n");
        return 0;
    }

    EXPECT_OP(PAUSE, state, state->next, end);
    pause_address = state->current;

    EXPECT_OP(LFENCE, state, state->next, end);
    EXPECT_OP(JMP, state, state->next, end);

    if (!memory_location_from_operand(state, &state->instruction->operands[0], state->next, &jmp_target)) {
        PVERBOSE(state, "Couldn't decode JMP target\n");
        return 0;
    }

    if (jmp_target != pause_address) { // Should JMP to PAUSE
        PVERBOSE(state, "Expected JMP to %p\n", pause_address);

        return 0;
    }

    while (DECODE(state, state->next, end)) {
        // Call target should point to the next instruction
        if (call_target == state->next) {
            *thunk_body = state->next;
            return 1;
        }

        if (state->instruction->mnemonic != ZYDIS_MNEMONIC_NOP) {
            break;
        }
    }

    PVERBOSE(state, "Expected CALL to point before %p\n", start);

    return 0;
}
#endif
