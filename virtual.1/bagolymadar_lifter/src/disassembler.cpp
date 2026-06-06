#include "disassembler.hpp"
#include <algorithm>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

Disassembler::Disassembler(std::span<const uint8_t> bytecode)
    : code_(bytecode) {}

uint16_t Disassembler::read_be16(uint16_t off) const {
  return (static_cast<uint16_t>(code_[off]) << 8) | code_[off + 1];
}

uint64_t Disassembler::read_be64(uint16_t off) const {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v = (v << 8) | code_[off + i];
  return v;
}

VmInstr Disassembler::decode_at(uint16_t pc) const {
  // Each instruction will start with the opcode, then
  // depending on the instruction, we will have different
  // operands and format of instructions.
  VmInstr instr{};
  instr.pc = pc;
  instr.op = static_cast<Opcode>(code_[pc]);
  const uint16_t op = pc + 1;

  switch (instr.op) {
  case Opcode::HLT:
  case Opcode::RET:
  case Opcode::LOADB_SERIAL:
  case Opcode::LOADB_NAME:
    // Just generate instruction with the opcode
    // and move to the next one.
    instr.next_pc = pc + 1;
    break;

  case Opcode::DEC:
  case Opcode::INC:
  case Opcode::PTR_NULL:
  case Opcode::CMPZ:
  case Opcode::PUSH_REG:
  case Opcode::POP_REG:
  case Opcode::NOT:
    // reg1 takes the value that is used in the operation
    // kept for the lifting process.
    instr.reg1 = code_[op];
    instr.next_pc = pc + 2;
    break;

  case Opcode::PUSH_IMM8:
    // Immediate value to push onto the stack
    // from this crackme is not consistent with
    // the pushed values
    instr.imm8 = code_[op];
    instr.next_pc = pc + 2;
    break;

  case Opcode::MOVQ:
  case Opcode::MOVB:
  case Opcode::ADD_REG:
  case Opcode::CMP_REG:
  case Opcode::ROL:
  case Opcode::XOR:
    // Operations with two registers, the registers
    // are implemented in memory from the VM
    instr.reg1 = code_[op];
    instr.reg2 = code_[op + 1];
    instr.next_pc = pc + 3;
    break;

  case Opcode::MOV_IMM8:
  case Opcode::CMP_IMM8:
  case Opcode::TEST_IMM8:
  case Opcode::SUB_IMM8:
  case Opcode::SHR:
  case Opcode::SHL:
    // Operations with a register and a IMM8
    // operand value.
    instr.reg1 = code_[op];
    instr.imm8 = code_[op + 1];
    instr.next_pc = pc + 3;
    break;

  case Opcode::JMP:
  case Opcode::JZ:
  case Opcode::JNZ:
  case Opcode::JL:
  case Opcode::CALL:
    // Offset where to jump from VM memory.
    instr.imm16 = read_be16(op);
    instr.next_pc = pc + 3;
    break;

  case Opcode::AND_IMM64:
  case Opcode::MOV_IMM64:
    // use of immediate 64 bit operands
    instr.reg1 = code_[op];
    instr.imm64 = read_be64(op + 1);
    instr.next_pc = pc + 10;
    break;

  default:
    throw std::runtime_error("Unknown opcode 0x" + std::to_string(code_[pc]) +
                             " at PC=" + std::to_string(pc));
  }
  return instr;
}

std::vector<VmInstr> Disassembler::disassemble(uint16_t start_pc) {
  std::vector<VmInstr> out;
  std::vector<std::uint8_t> visited(code_.size(), false);
  std::vector<std::uint16_t> worklist = {start_pc};
  // Disassembly loop, we will follow a recursive descent
  // approach
  while (!worklist.empty()) {
    uint16_t pc = worklist.back();
    worklist.pop_back();

    while (pc < static_cast<uint16_t>(code_.size()) && !visited[pc]) {
      visited[pc] = true;
      // get instruction
      VmInstr instr = decode_at(pc);
      out.push_back(instr);
      // Analyze instruction to know where to keep disassembling
      switch (instr.op) {
      case Opcode::HLT:
      case Opcode::RET:
        goto next_in_worklist;

      case Opcode::JMP:
        worklist.push_back(instr.imm16);
        goto next_in_worklist;

      case Opcode::JZ:
      case Opcode::JNZ:
      case Opcode::JL:
        worklist.push_back(instr.imm16);
        pc = instr.next_pc;
        continue;

      // CALL must not fall through linearly into the return site.
      // Push both the callee entry and the return site as separate
      // leaders, then stop linear flow exactly like JMP does.
      case Opcode::CALL:
        worklist.push_back(instr.imm16);   // callee entry
        worklist.push_back(instr.next_pc); // return site
        goto next_in_worklist;

      default:
        pc = instr.next_pc;
        continue;
      }
    next_in_worklist:;
    }
  }

  std::sort(out.begin(), out.end(),
            [](const VmInstr &a, const VmInstr &b) { return a.pc < b.pc; });
  return out;
}