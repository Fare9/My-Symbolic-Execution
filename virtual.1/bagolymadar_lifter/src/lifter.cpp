#include "lifter.hpp"

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>

#include <set>
#include <stdexcept>

static const char *reg_name(uint8_t idx) {
  static const char *names[] = {"ACC",  "R1",     "RESULT", "PC",
                                "NAME", "SERIAL", "FLAGS",  "SP"};
  return idx < 8 ? names[idx] : "UNK";
}

Lifter::Lifter(llvm::LLVMContext &ctx, llvm::Module &mod)
    : ctx_(ctx), mod_(mod) {}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

llvm::Function *Lifter::lift(const std::vector<VmInstr> &instrs,
                             const std::string &fname) {
  auto *i64t = llvm::Type::getInt64Ty(ctx_);
  auto *ptrt = llvm::PointerType::get(ctx_, 0);

  auto *fty = llvm::FunctionType::get(i64t, {ptrt, ptrt}, false);
  func_ =
      llvm::Function::Create(fty, llvm::Function::ExternalLinkage, fname, mod_);
  func_->getArg(0)->setName("name_arg");
  func_->getArg(1)->setName("serial_arg");

  auto *entry = llvm::BasicBlock::Create(ctx_, "entry", func_);
  llvm::IRBuilder<> eb(entry);

  for (int i = 0; i < NUM_REGS; ++i)
    regs_[i] = eb.CreateAlloca(i64t, nullptr, reg_name(i));

  eb.CreateStore(eb.CreatePtrToInt(func_->getArg(0), i64t),
                 regs_[static_cast<uint8_t>(Reg::NAME)]);
  eb.CreateStore(eb.CreatePtrToInt(func_->getArg(1), i64t),
                 regs_[static_cast<uint8_t>(Reg::SERIAL)]);

  auto *arr_ty = llvm::ArrayType::get(eb.getInt8Ty(), STACK_SIZE);
  stack_mem_ = eb.CreateAlloca(arr_ty, nullptr, "vm_stack");
  sp_alloca_  = eb.CreateAlloca(i64t, nullptr, "sp");
  eb.CreateStore(eb.getInt64(STACK_SIZE), sp_alloca_);

  // Build callee -> return-site map from all CALL instructions.
  // This gives RET a static lookup table keyed on the callee entry PC
  // instead of relying on a linear sp_ simulation (which breaks when the
  // sorted instruction list interleaves code from different call depths).
  for (const auto &instr : instrs) {
    if (instr.op == Opcode::CALL)
      call_return_sites_[instr.imm16].insert(instr.next_pc);
  }

  pass1_create_blocks(instrs);

  eb.CreateBr(get_block(instrs.front().pc));

  pass2_emit_ir(instrs);

  return func_;
}

// ---------------------------------------------------------------------------
// Pass 1 — identify leaders and pre-create BasicBlocks
// ---------------------------------------------------------------------------

void Lifter::pass1_create_blocks(const std::vector<VmInstr> &instrs) {
  std::set<uint16_t> leaders;
  leaders.insert(instrs.front().pc);

  for (const auto &instr : instrs) {
    switch (instr.op) {
    case Opcode::JMP:
      leaders.insert(instr.imm16);
      break;
    case Opcode::JZ:
    case Opcode::JNZ:
    case Opcode::JL:
      leaders.insert(instr.imm16);
      leaders.insert(instr.next_pc);
      break;
    case Opcode::CALL:
      leaders.insert(instr.imm16);   // callee entry
      leaders.insert(instr.next_pc); // return site
      break;
    default:
      break;
    }
  }

  for (uint16_t pc : leaders)
    blocks_[pc] =
        llvm::BasicBlock::Create(ctx_, "bb_" + std::to_string(pc), func_);
}

// ---------------------------------------------------------------------------
// Pass 2 — emit IR
// ---------------------------------------------------------------------------

void Lifter::pass2_emit_ir(const std::vector<VmInstr> &instrs) {
  llvm::IRBuilder<> builder(ctx_);
  llvm::BasicBlock *cur = nullptr;

  for (const auto &instr : instrs) {
    if (auto it = blocks_.find(instr.pc); it != blocks_.end()) {
      auto *next_bb = it->second;
      if (cur && !cur->getTerminator())
        llvm::IRBuilder<>(cur).CreateBr(next_bb);
      cur = next_bb;
      builder.SetInsertPoint(cur);
      if (call_return_sites_.count(instr.pc))
        current_callee_entry_ = instr.pc;
    }
    emit_instr(instr, builder);
  }
}

// ---------------------------------------------------------------------------
// Instruction emitter
// ---------------------------------------------------------------------------

void Lifter::emit_instr(const VmInstr &instr, llvm::IRBuilder<> &b) {
  auto *i64t = b.getInt64Ty();
  auto *i8t = b.getInt8Ty();
  auto *ptrt = b.getPtrTy();

  auto load_b = [&](uint8_t idx) { return load_reg(idx, b); };
  auto store_b = [&](uint8_t idx, llvm::Value *v) { store_reg(idx, v, b); };

  switch (instr.op) {

  case Opcode::MOVQ:
    store_b(instr.reg1, load_b(instr.reg2));
    break;

  case Opcode::MOVB: {
    auto *src_byte = b.CreateTrunc(load_b(instr.reg2), i8t);
    auto *dst = load_b(instr.reg1);
    auto *masked = b.CreateAnd(dst, ~0xFFULL);
    store_b(instr.reg1, b.CreateOr(masked, b.CreateZExt(src_byte, i64t)));
    break;
  }

  case Opcode::MOV_IMM8:
    store_b(instr.reg1, b.getInt64(instr.imm8));
    break;

  case Opcode::MOV_IMM64:
    store_b(instr.reg1, b.getInt64(instr.imm64));
    break;

  case Opcode::LOADB_NAME: {
    auto *ptr = b.CreateIntToPtr(load_b(static_cast<uint8_t>(Reg::NAME)), ptrt);
    auto *byte = b.CreateLoad(i8t, ptr, "name_byte");
    store_b(static_cast<uint8_t>(Reg::ACC), b.CreateZExt(byte, i64t));
    store_b(
        static_cast<uint8_t>(Reg::NAME),
        b.CreateAdd(load_b(static_cast<uint8_t>(Reg::NAME)), b.getInt64(1)));
    break;
  }

  case Opcode::LOADB_SERIAL: {
    auto *ptr =
        b.CreateIntToPtr(load_b(static_cast<uint8_t>(Reg::SERIAL)), ptrt);
    auto *byte = b.CreateLoad(i8t, ptr, "serial_byte");
    store_b(static_cast<uint8_t>(Reg::ACC), b.CreateZExt(byte, i64t));
    store_b(
        static_cast<uint8_t>(Reg::SERIAL),
        b.CreateAdd(load_b(static_cast<uint8_t>(Reg::SERIAL)), b.getInt64(1)));
    break;
  }

  case Opcode::INC:
    store_b(instr.reg1, b.CreateAdd(load_b(instr.reg1), b.getInt64(1)));
    break;

  case Opcode::DEC:
    store_b(instr.reg1, b.CreateSub(load_b(instr.reg1), b.getInt64(1)));
    break;

  case Opcode::ADD_REG:
    store_b(instr.reg1, b.CreateAdd(load_b(instr.reg1), load_b(instr.reg2)));
    break;

  case Opcode::SUB_IMM8: {
    auto *byte = b.CreateTrunc(load_b(instr.reg1), i8t);
    auto *result = b.CreateSub(byte, b.getInt8(instr.imm8));
    auto *upper = b.CreateAnd(load_b(instr.reg1), ~0xFFULL);
    store_b(instr.reg1, b.CreateOr(upper, b.CreateZExt(result, i64t)));
    break;
  }

  case Opcode::AND_IMM64:
    store_b(instr.reg1,
            b.CreateAnd(load_b(instr.reg1), b.getInt64(instr.imm64)));
    break;

  case Opcode::SHL:
    store_b(instr.reg1,
            b.CreateShl(load_b(instr.reg1), b.getInt64(instr.imm8)));
    break;

  case Opcode::SHR:
    store_b(instr.reg1,
            b.CreateLShr(load_b(instr.reg1), b.getInt64(instr.imm8)));
    break;

  case Opcode::ROL: {
    auto *val = load_b(instr.reg1);
    auto *amt = b.CreateAnd(load_b(instr.reg2), b.getInt64(63));
    auto *inv = b.CreateSub(b.getInt64(64), amt);
    store_b(instr.reg1,
            b.CreateOr(b.CreateShl(val, amt), b.CreateLShr(val, inv)));
    break;
  }

  case Opcode::NOT: {
    auto *byte = b.CreateNot(b.CreateTrunc(load_b(instr.reg1), i8t));
    auto *upper = b.CreateAnd(load_b(instr.reg1), ~0xFFULL);
    store_b(instr.reg1, b.CreateOr(upper, b.CreateZExt(byte, i64t)));
    break;
  }

  case Opcode::XOR: {
    auto *lhs = b.CreateTrunc(load_b(instr.reg1), i8t);
    auto *rhs = b.CreateTrunc(load_b(instr.reg2), i8t);
    auto *upper = b.CreateAnd(load_b(instr.reg1), ~0xFFULL);
    store_b(instr.reg1,
            b.CreateOr(upper, b.CreateZExt(b.CreateXor(lhs, rhs), i64t)));
    break;
  }

  case Opcode::CMPZ: {
    auto *is_zero = b.CreateICmpEQ(load_b(instr.reg1), b.getInt64(0));
    set_flag_bit(0, is_zero, b);
    break;
  }

  case Opcode::PTR_NULL: {
    auto *ptr = b.CreateIntToPtr(load_b(instr.reg1), ptrt);
    auto *byte = b.CreateLoad(i8t, ptr);
    auto *is_zero = b.CreateICmpEQ(byte, b.getInt8(0));
    set_flag_bit(0, is_zero, b);
    break;
  }

  case Opcode::CMP_IMM8: {
    auto *val = load_b(instr.reg1);
    auto *imm = b.getInt64(instr.imm8);
    set_cmp_flags(b.CreateICmpEQ(val, imm), b.CreateICmpSLT(val, imm), b);
    break;
  }

  case Opcode::CMP_REG: {
    auto *lhs = load_b(instr.reg1);
    auto *rhs = load_b(instr.reg2);
    set_cmp_flags(b.CreateICmpEQ(lhs, rhs), b.CreateICmpSLT(lhs, rhs), b);
    break;
  }

  case Opcode::TEST_IMM8: {
    auto *result = b.CreateAnd(load_b(instr.reg1), b.getInt64(instr.imm8));
    auto *is_zero = b.CreateICmpEQ(result, b.getInt64(0));
    set_flag_bit(0, is_zero, b);
    break;
  }

  case Opcode::JMP:
    b.CreateBr(get_block(instr.imm16));
    break;

  case Opcode::JZ: {
    auto *zf =
        b.CreateAnd(load_b(static_cast<uint8_t>(Reg::FLAGS)), b.getInt64(1));
    auto *cond = b.CreateICmpNE(zf, b.getInt64(0));
    b.CreateCondBr(cond, get_block(instr.imm16), get_block(instr.next_pc));
    break;
  }

  case Opcode::JNZ: {
    auto *zf =
        b.CreateAnd(load_b(static_cast<uint8_t>(Reg::FLAGS)), b.getInt64(1));
    auto *cond = b.CreateICmpEQ(zf, b.getInt64(0));
    b.CreateCondBr(cond, get_block(instr.imm16), get_block(instr.next_pc));
    break;
  }

  case Opcode::JL: {
    auto *lt =
        b.CreateAnd(load_b(static_cast<uint8_t>(Reg::FLAGS)), b.getInt64(2));
    auto *cond = b.CreateICmpNE(lt, b.getInt64(0));
    b.CreateCondBr(cond, get_block(instr.imm16), get_block(instr.next_pc));
    break;
  }

  case Opcode::PUSH_IMM8:
    push_val(b.getInt8(instr.imm8), 1, b);
    break;

  case Opcode::PUSH_REG:
    push_val(load_b(instr.reg1), 8, b);
    break;

  case Opcode::POP_REG:
    store_b(instr.reg1, pop_val(8, i64t, b));
    break;

  case Opcode::CALL:
    // Push the return address so the VM stack stays consistent at
    // runtime, then branch to the callee.
    push_val(b.getInt16(instr.next_pc), 2, b);
    b.CreateBr(get_block(instr.imm16));
    break;

  case Opcode::RET: {
    auto *ret_addr = pop_val(2, b.getInt16Ty(), b);

    auto it = call_return_sites_.find(current_callee_entry_);
    if (it == call_return_sites_.end() || it->second.empty())
      throw std::runtime_error("RET at PC=" + std::to_string(instr.pc) +
                               " has no known return sites");

    const auto &sites = it->second;
    if (sites.size() == 1) {
      b.CreateBr(get_block(*sites.begin()));
    } else {
      auto *unreachable_bb =
          llvm::BasicBlock::Create(ctx_, "ret_dispatch_default", func_);
      llvm::IRBuilder<>(unreachable_bb).CreateUnreachable();
      auto *sw = b.CreateSwitch(ret_addr, unreachable_bb,
                                static_cast<unsigned>(sites.size()));
      for (uint16_t site : sites)
        sw->addCase(b.getInt16(site), get_block(site));
    }
    break;
  }
  case Opcode::HLT:
    b.CreateRet(load_b(static_cast<uint8_t>(Reg::RESULT)));
    break;

  default:
    throw std::runtime_error("Unhandled opcode in emit_instr");
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

llvm::Value *Lifter::load_reg(uint8_t idx, llvm::IRBuilder<> &b) {
  return b.CreateLoad(b.getInt64Ty(), regs_[idx], reg_name(idx));
}

void Lifter::store_reg(uint8_t idx, llvm::Value *val, llvm::IRBuilder<> &b) {
  if (val->getType() != b.getInt64Ty())
    val = b.CreateZExt(val, b.getInt64Ty());
  b.CreateStore(val, regs_[idx]);
}

void Lifter::push_val(llvm::Value *val, unsigned width_bytes,
                      llvm::IRBuilder<> &b) {
  auto *i64t   = b.getInt64Ty();
  auto *arr_ty = llvm::ArrayType::get(b.getInt8Ty(), STACK_SIZE);
  auto *sp     = b.CreateLoad(i64t, sp_alloca_, "sp");
  auto *new_sp = b.CreateSub(sp, b.getInt64(width_bytes));
  b.CreateStore(new_sp, sp_alloca_);
  auto *gep = b.CreateGEP(arr_ty, stack_mem_, {b.getInt64(0), new_sp}, "sp_slot");
  b.CreateStore(val, gep);
}

llvm::Value *Lifter::pop_val(unsigned width_bytes, llvm::Type *ty,
                             llvm::IRBuilder<> &b) {
  auto *i64t   = b.getInt64Ty();
  auto *arr_ty = llvm::ArrayType::get(b.getInt8Ty(), STACK_SIZE);
  auto *sp     = b.CreateLoad(i64t, sp_alloca_, "sp");
  auto *gep    = b.CreateGEP(arr_ty, stack_mem_, {b.getInt64(0), sp}, "sp_slot");
  auto *val    = b.CreateLoad(ty, gep, "popped");
  auto *new_sp = b.CreateAdd(sp, b.getInt64(width_bytes));
  b.CreateStore(new_sp, sp_alloca_);
  return val;
}

void Lifter::set_flag_bit(int bit, llvm::Value *cond_i1, llvm::IRBuilder<> &b) {
  uint8_t fidx = static_cast<uint8_t>(Reg::FLAGS);
  auto *flags = load_reg(fidx, b);
  auto *cleared = b.CreateAnd(flags, ~(1ULL << bit));
  auto *bit_val =
      b.CreateShl(b.CreateZExt(cond_i1, b.getInt64Ty()), b.getInt64(bit));
  store_reg(fidx, b.CreateOr(cleared, bit_val), b);
}

void Lifter::set_cmp_flags(llvm::Value *eq_i1, llvm::Value *lt_i1,
                           llvm::IRBuilder<> &b) {
  uint8_t fidx = static_cast<uint8_t>(Reg::FLAGS);
  auto *flags = load_reg(fidx, b);
  auto *cleared = b.CreateAnd(flags, ~3ULL);
  auto *eq_bit = b.CreateZExt(eq_i1, b.getInt64Ty());
  auto *lt_bit =
      b.CreateShl(b.CreateZExt(lt_i1, b.getInt64Ty()), b.getInt64(1));
  store_reg(fidx, b.CreateOr(cleared, b.CreateOr(eq_bit, lt_bit)), b);
}

llvm::BasicBlock *Lifter::get_block(uint16_t pc) {
  auto it = blocks_.find(pc);
  if (it == blocks_.end())
    throw std::runtime_error("No basic block for PC=" + std::to_string(pc));
  return it->second;
}