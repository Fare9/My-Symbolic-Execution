#pragma once
#include "disassembler.hpp"
#include "vm_defs.hpp"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <set>
#include <string>
#include <unordered_map>
#include <vector>

class Lifter {
public:
  Lifter(llvm::LLVMContext &ctx, llvm::Module &mod);

  // Lift the decoded instruction stream into an LLVM function.
  // The function signature is: i64 @name(ptr %name_arg, ptr %serial_arg)
  llvm::Function *lift(const std::vector<VmInstr> &instrs,
                       const std::string &fname = "vm_func");

private:
  // Pass 1: walk instrs and pre-create a BasicBlock for every branch
  // target/leader.
  void pass1_create_blocks(const std::vector<VmInstr> &instrs);

  // Pass 2: emit IR for every instruction, switching blocks at leaders.
  void pass2_emit_ir(const std::vector<VmInstr> &instrs);

  // For generating a code that resembles the one from the VM
  void emit_instr(const VmInstr &instr, llvm::IRBuilder<> &b);

  // Register helpers, all registers are alloca i64.
  // NAME (4) and SERIAL (5) hold addresses as integers; use inttoptr when
  // dereferencing.
  llvm::Value *load_reg(uint8_t idx, llvm::IRBuilder<> &b);
  void store_reg(uint8_t idx, llvm::Value *val, llvm::IRBuilder<> &b);

  // Stack helpers, stack_mem_ is alloca [STACK_SIZE x i8].
  // sp_ is the C++ integer offset (grows downward); all GEP indices are
  // constants so SROA can split the array and mem2reg can promote each slot to
  // SSA.
  // The idea of using an allocated memory in LLVM directly comes from the
  // next blogpost: https://eversinc33.com/2026/05/07/llvm-devirtualizer
  void push_val(llvm::Value *val, unsigned width_bytes, llvm::IRBuilder<> &b);
  llvm::Value *pop_val(unsigned width_bytes, llvm::Type *ty,
                       llvm::IRBuilder<> &b);

  // FLAGS helpers
  void set_flag_bit(int bit, llvm::Value *cond_i1, llvm::IRBuilder<> &b);
  void set_cmp_flags(llvm::Value *eq_i1, llvm::Value *lt_i1,
                     llvm::IRBuilder<> &b);

  llvm::BasicBlock *get_block(uint16_t pc);

  llvm::LLVMContext &ctx_;
  llvm::Module &mod_;
  llvm::Function *func_ = nullptr;

  std::array<llvm::AllocaInst *, NUM_REGS> regs_{};
  llvm::AllocaInst *stack_mem_ = nullptr;
  // Runtime SP: an alloca i64 holding the current stack byte offset.
  // Dynamic GEPs are required because the same callee can be reached from
  // multiple call sites with different stack depths, so a compile-time
  // integer sp_ would produce wrong (aliased) GEP indices.
  llvm::AllocaInst *sp_alloca_ = nullptr;

  // Maps callee_entry_pc -> set of all return PCs that CALL into it.
  // Built once in lift() before any IR is emitted.
  std::unordered_map<uint16_t, std::set<uint16_t>> call_return_sites_;

  // Entry PC of the callee currently being emitted.
  // Updated by pass2_emit_ir() whenever it enters a block that is
  // a callee entry (a key in call_return_sites_).
  uint16_t current_callee_entry_ = 0;

  std::unordered_map<uint16_t, llvm::BasicBlock *> blocks_;
};