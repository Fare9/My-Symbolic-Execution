#include "disassembler.hpp"
#include "lifter.hpp"
#include "optimizer.hpp"

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <vector>

static const char *reg_str(uint8_t idx) {
  static const char *n[] = {"ACC",  "R1",     "RESULT", "PC",
                            "NAME", "SERIAL", "FLAGS",  "SP"};
  return idx < 8 ? n[idx] : "?";
}

static std::string opcode_str(Opcode op) {
  switch (op) {
  case Opcode::MOVQ:
    return "MOVQ";
  case Opcode::MOVB:
    return "MOVB";
  case Opcode::PUSH_IMM8:
    return "PUSH_IMM8";
  case Opcode::JMP:
    return "JMP";
  case Opcode::DEC:
    return "DEC";
  case Opcode::PTR_NULL:
    return "PTR_NULL";
  case Opcode::INC:
    return "INC";
  case Opcode::HLT:
    return "HLT";
  case Opcode::LOADB_SERIAL:
    return "LOADB_SERIAL";
  case Opcode::CMPZ:
    return "CMPZ";
  case Opcode::JZ:
    return "JZ";
  case Opcode::MOV_IMM8:
    return "MOV_IMM8";
  case Opcode::LOADB_NAME:
    return "LOADB_NAME";
  case Opcode::CMP_IMM8:
    return "CMP_IMM8";
  case Opcode::JNZ:
    return "JNZ";
  case Opcode::PUSH_REG:
    return "PUSH_REG";
  case Opcode::POP_REG:
    return "POP_REG";
  case Opcode::SHR:
    return "SHR";
  case Opcode::TEST_IMM8:
    return "TEST_IMM8";
  case Opcode::ADD_REG:
    return "ADD_REG";
  case Opcode::AND_IMM64:
    return "AND_IMM64";
  case Opcode::JL:
    return "JL";
  case Opcode::SUB_IMM8:
    return "SUB_IMM8";
  case Opcode::SHL:
    return "SHL";
  case Opcode::CMP_REG:
    return "CMP_REG";
  case Opcode::MOV_IMM64:
    return "MOV_IMM64";
  case Opcode::ROL:
    return "ROL";
  case Opcode::NOT:
    return "NOT";
  case Opcode::XOR:
    return "XOR";
  case Opcode::CALL:
    return "CALL";
  case Opcode::RET:
    return "RET";
  default:
    return "???";
  }
}

static void print_disassembly(const std::vector<VmInstr> &instrs) {
  std::cerr << "\n--- VM disassembly ---\n";
  for (const auto &i : instrs) {
    std::ostringstream line;
    line << "  " << std::hex << std::setw(4) << std::setfill('0') << i.pc
         << "  " << std::left << std::setw(14) << opcode_str(i.op);

    switch (i.op) {
    // reg, reg
    case Opcode::MOVQ:
    case Opcode::MOVB:
    case Opcode::ADD_REG:
    case Opcode::CMP_REG:
    case Opcode::ROL:
    case Opcode::XOR:
      line << reg_str(i.reg1) << ", " << reg_str(i.reg2);
      break;
    // reg
    case Opcode::DEC:
    case Opcode::INC:
    case Opcode::PTR_NULL:
    case Opcode::CMPZ:
    case Opcode::PUSH_REG:
    case Opcode::POP_REG:
    case Opcode::NOT:
      line << reg_str(i.reg1);
      break;
    // reg, imm8
    case Opcode::MOV_IMM8:
    case Opcode::CMP_IMM8:
    case Opcode::TEST_IMM8:
    case Opcode::SUB_IMM8:
    case Opcode::SHR:
    case Opcode::SHL:
      line << reg_str(i.reg1) << ", 0x" << std::hex << static_cast<int>(i.imm8);
      break;
    // imm8
    case Opcode::PUSH_IMM8:
      line << "0x" << std::hex << static_cast<int>(i.imm8);
      break;
    // imm16 (jump/call target)
    case Opcode::JMP:
    case Opcode::JZ:
    case Opcode::JNZ:
    case Opcode::JL:
    case Opcode::CALL:
      line << "0x" << std::hex << i.imm16;
      break;
    // reg, imm64
    case Opcode::AND_IMM64:
    case Opcode::MOV_IMM64:
      line << reg_str(i.reg1) << ", 0x" << std::hex << i.imm64;
      break;
    // no operands
    default:
      break;
    }
    std::cerr << line.str() << '\n';
  }
  std::cerr << "--- end ---\n\n";
}

static std::vector<uint8_t> load_file(const char *path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    std::cerr << "Cannot open: " << path << '\n';
    std::exit(1);
  }
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: vm_lifter <bytecode.bin> [start_pc=0]\n";
    return 1;
  }

  auto bcode = load_file(argv[1]);
  uint16_t start_pc = argc > 2 ? static_cast<uint16_t>(std::stoi(argv[2])) : 0;

  // --- disassemble ---------------------------------------------------------
  Disassembler dis{std::span<const uint8_t>(bcode)};
  auto instrs = dis.disassemble(start_pc);

  std::cerr << "[+] Decoded " << instrs.size() << " instructions\n";
  print_disassembly(instrs);

  // --- lift to LLVM IR -----------------------------------------------------
  llvm::LLVMContext ctx;
  auto mod = std::make_unique<llvm::Module>("vm_lifted", ctx);

  Lifter lifter(ctx, *mod);
  auto *func = lifter.lift(instrs, "vm_func");
  (void)func;

  std::cerr << "[+] Lifted to IR\n";

  // Verify before optimising
  if (llvm::verifyModule(*mod, &llvm::errs())) {
    std::cerr << "[-] IR verification failed (pre-opt)\n";
    return 1;
  }

  mod->print(llvm::outs(), nullptr);

  // --- optimise ------------------------------------------------------------
  optimize(*mod);
  std::cerr << "[+] Optimized\n";

  if (llvm::verifyModule(*mod, &llvm::errs())) {
    std::cerr << "[-] IR verification failed (post-opt)\n";
    return 1;
  }

  // --- emit ----------------------------------------------------------------
  mod->print(llvm::outs(), nullptr);
  return 0;
}
