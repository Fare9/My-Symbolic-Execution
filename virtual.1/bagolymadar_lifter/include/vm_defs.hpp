#pragma once
#include <cstdint>

/// Opcodes retrieved from the reverse engineering of each
/// one of the handlers.
enum class Opcode : uint8_t {
  MOVQ = 0x01,
  MOVB = 0x02,
  PUSH_IMM8 = 0x09,
  JMP = 0x11,
  DEC = 0x14,
  PTR_NULL = 0x1E,
  INC = 0x41,
  HLT = 0x4C,
  LOADB_SERIAL = 0x52,
  CMPZ = 0x54,
  JZ = 0x55,
  MOV_IMM8 = 0x56,
  LOADB_NAME = 0x69,
  CMP_IMM8 = 0x7F,
  JNZ = 0x81,
  PUSH_REG = 0x8D,
  POP_REG = 0x8E,
  SHR = 0x8F,
  TEST_IMM8 = 0x90,
  ADD_REG = 0x93,
  AND_IMM64 = 0x94,
  JL = 0x95,
  SUB_IMM8 = 0x96,
  SHL = 0x97,
  CMP_REG = 0x98,
  MOV_IMM64 = 0x99,
  ROL = 0x9A,
  NOT = 0x9B,
  XOR = 0x9C,
  CALL = 0xAB,
  RET = 0xBA,
};

// Register indices as used in opcode operands: vm_struct base + (idx * 8)
enum class Reg : uint8_t {
  ACC = 0,    // +0x00  general purpose
  R1 = 1,     // +0x08  general purpose
  RESULT = 2, // +0x10  return value
  PC = 3,     // +0x18  (not a real operand target; control flow in IR)
  // We need the real pointers, they will be provided as arguments
  // to the vm_function
  NAME = 4,   // +0x20  char* input pointer
  SERIAL = 5, // +0x28  char* input pointer
  FLAGS = 6,  // +0x30  bit0=ZF, bit1=LT
  SP = 7,     // +0x38  (managed implicitly by lifter stack tracking)
};

// FLAGS layout
static constexpr uint64_t FLAG_ZF = (1ULL << 0); // zero / equal
static constexpr uint64_t FLAG_LT = (1ULL << 1); // less-than (signed)

static constexpr int NUM_REGS = 8;
static constexpr int STACK_SIZE =
    128; // bytes; struct has 0x80 bytes of stack space
