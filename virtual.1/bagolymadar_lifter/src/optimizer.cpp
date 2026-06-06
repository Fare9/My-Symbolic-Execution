#include "optimizer.hpp"

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Analysis/CGSCCPassManager.h>

void optimize(llvm::Module& mod) {
    llvm::PassBuilder pb;

    llvm::LoopAnalysisManager    lam;
    llvm::FunctionAnalysisManager fam;
    llvm::CGSCCAnalysisManager   cgam;
    llvm::ModuleAnalysisManager  mam;

    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);

    // O1 pipeline:
    //   SROA       — splits [N x i8] stack alloca into per-slot scalars
    //   mem2reg    — promotes per-slot scalars (and register allocas) to SSA
    //   instcombine — collapses trunc/zext/or chains from byte-level ops
    //   simplifycfg — merges trivial blocks from the VM dispatch layer
    //   SCCP / GVN  — constant-propagates through flag checks
    //   DSE / DCE   — removes dead stack stores whose value is never read
    auto mpm = pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);
    mpm.run(mod, mam);
}
