#pragma once
#include <llvm/IR/Module.h>

// Run LLVM O1 pipeline on mod.
// Key passes that collapse the VM layer:
//   mem2reg  — promotes register/stack allocas to SSA values
//   SROA     — splits the [N x i8] stack alloca into per-slot scalars first
//   instcombine — folds trunc/zext chains from byte-level ops (NOT, XOR, MOVB, SUB_IMM8)
//   simplifycfg — merges trivial blocks left over from the VM dispatch
//   SCCP / GVN  — propagates constants, resolves flag checks whose value is known
//   DSE / DCE   — removes dead stack stores whose loaded value is never used
void optimize(llvm::Module& mod);
