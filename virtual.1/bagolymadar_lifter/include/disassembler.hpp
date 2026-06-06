#pragma once
#include "vm_defs.hpp"
#include <cstdint>
#include <span>
#include <vector>

/// Structure directly retrieved from the reverse engineering of the
/// VM. The opcodes are also retrieved from the analysis of the handlers.
struct VmInstr {
    uint16_t pc      = 0;
    Opcode   op      = Opcode::HLT;
    uint8_t  reg1    = 0;   // dst (or only) register operand
    uint8_t  reg2    = 0;   // src register operand
    uint8_t  imm8    = 0;
    uint16_t imm16   = 0;   // big-endian jump/call target
    uint64_t imm64   = 0;   // big-endian 64-bit immediate (AND_IMM64, MOV_IMM64)
    uint16_t next_pc = 0;   // address of the following instruction
};

class Disassembler {
public:
    explicit Disassembler(std::span<const uint8_t> bytecode);

    // Recursive-descent decode starting at start_pc, following all reachable paths.
    std::vector<VmInstr> disassemble(uint16_t start_pc = 0);

private:
    [[nodiscard]] VmInstr  decode_at(uint16_t pc) const;
    [[nodiscard]] uint16_t read_be16(uint16_t offset) const;
    [[nodiscard]] uint64_t read_be64(uint16_t offset) const;
    // The code will be directly taken from a dump of the crackme.
    std::span<const uint8_t> code_;
};
