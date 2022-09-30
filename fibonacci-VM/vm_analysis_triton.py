#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from pickletools import optimize
from triton import *

import string
import lief
import sys
import os

# Target binary
TARGET="./vm_basic.bin"

# Global settings
SYMBOLIC = True
CONCRETE = not SYMBOLIC

DEBUG = True

# Memory mapping
BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_STACK = 0x9ffffff0
ERRNO      = 0xa0000000

#######################################################################
# emulated functions, write here those you want to emulate! ###########
#######################################################################

def atoi(triton_ctx):
    '''
    Emulate the atoi routine, here we will say that the
    returned value must be a symbolic value.
    '''
    print("[+] atoi hooked")

    return(SYMBOLIC, 6)

def libc_start_main(ctx):
    print('[+] __libc_start_main hooked')

    # Get arguments
    main = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    # Push the return value to jump into the main() function
    ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)-CPUSIZE.QWORD)

    # set as return value the address of main
    # avoid all the libc stuff
    ret2main = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD)
    ctx.setConcreteMemoryValue(ret2main, main)

    # Setup argc / argv
    ctx.concretizeRegister(ctx.registers.rdi)
    ctx.concretizeRegister(ctx.registers.rsi)

    # here write all the needed arguments
    argvs = [
        bytes(TARGET.encode('utf-8')),  # argv[0]
        b"test!"
    ]

    # Define argc / argv
    base  = BASE_ARGV
    addrs = list()

    # create the arguments
    index = 0
    for argv in argvs:
        addrs.append(base)
        ctx.setConcreteMemoryAreaValue(base, argv+b'\x00')
        base += len(argv)+1
        print('[+] argv[%d] = %s' %(index, argv))
        index += 1

    # set the pointer to the arguments
    argc = len(argvs)
    argv = base
    for addr in addrs:
        ctx.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    # finally set RDI and RSI values
    ctx.setConcreteRegisterValue(ctx.registers.rdi, argc)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, argv)

    return (CONCRETE, 0)

#######################################################################
# Useful Functions always present! ####################################
#######################################################################

customRelocation = [
    ['atoi', atoi, None],
    ['__libc_start_main', libc_start_main, None]
]

def getMemoryString(ctx, addr):
    '''
    Function to extract a python string from
    a memory address, we will read a c-style
    string, reading the concrete memory value.
    '''
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr+index):
        c = chr(ctx.getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s

# Lief functions!

def loadBinary(triton_ctx, lief_binary):
    '''
    Use Lief parser in order to retrieve
    information of the binary, and load it
    in Triton's memory.

    :param triton_ctx: context where triton stores all the information.
    :param lief_binary: parser of lief with information about the headers.
    '''
    phdrs = lief_binary.segments
    for phdr in phdrs:
        size    = phdr.physical_size
        vaddr   = phdr.virtual_address
        print("[+] Loading 0x%06x - 0x%06x" % (vaddr, vaddr+size))
        triton_ctx.setConcreteMemoryAreaValue(vaddr, list(phdr.content))
    return

def makeRelocation(ctx, binary):
    '''
    Extract the addresses from the PLT, these will be used
    to retrieve the addressed and hook the functions once we have to run them.

    :param ctx: triton context for the emulation.
    :param binary: lief binary parser.
    '''
    # Setup plt
    print("[+] Applying relocations and extracting the addresses for the external functions")

    for pltIndex in range(len(customRelocation)):
        customRelocation[pltIndex][2] = BASE_PLT + pltIndex

    relocations = [x for x in binary.pltgot_relocations]
    relocations.extend([x for x in binary.dynamic_relocations])

    # Perform our own relocations
    for rel in relocations:
        symbolName = rel.symbol.name
        symbolRelo = rel.address
        for crel in customRelocation:
            if symbolName == crel[0]:
                print('[+] Init PLT for: %s' %(symbolName))
                ctx.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
                break
    return

def hookingHandler(ctx):
    '''
    In case one of the run address is one from
    the emulated functions, just call it and
    get the result, check if it's needed to symbolize
    the output register.

    :param ctx: Triton's context for emulation.
    '''
    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    for rel in customRelocation:
        if rel[2] == pc:
            # Emulate the routine and the return value
            state, ret_value = rel[1](ctx)
            if ret_value is not None:
                ctx.setConcreteRegisterValue(ctx.registers.rax, ret_value)
                if state is SYMBOLIC:
                    print(f'[+] Symbolizing the return value')
                    ctx.symbolizeRegister(ctx.registers.rax)
            # Get the return address
            ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))
            # Hijack RIP to skip the call
            ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)
            # Restore RSP (simulate the ret)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)+CPUSIZE.QWORD)
    return

# here it comes the good part!

def emulate(ctx, pc):
    global DEBUG

    while pc:
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

        # create the instruction to emulate
        instruction = Instruction(pc, opcodes)
        ctx.processing(instruction)

        if DEBUG:
            print(f"0x{pc:08X}: {str(instruction)}")
        
        # stop if halt executed
        # or incase we reached the end address
        if instruction.getType() == OPCODE.X86.HLT or pc == 0x12ed:
            # Get Symbolic expression of RAX
            raxExpr = ctx.getSymbolicRegisters()[REG.X86_64.RAX]
            # Backward slice the RAX expression.
            slicing = ctx.sliceExpressions(raxExpr)
            # Sort the slicing and display all expressions with their comments
            for k, v in sorted(slicing.items()):
                # Here we display the comment to understand the correspondence
                # between an expression and its referenced instruction.
                print('[slicing]', v.getComment())
            break
        
            
        hookingHandler(ctx)

        # Next
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

def print_expression_and_lift(ctx):
    '''
    Method to print the expression from the final number
    extract the register and extract the AST.
    '''
    rax = ctx.getRegisterAst(ctx.registers.rax)
    ast = ctx.getAstContext()
    rax_ast = ast.unroll(rax)

    print("[!] Solving value to get 8")
    m = ctx.getModel(rax_ast == 8)
    for k, v in m.items():
        print(f"{k} = {v}")

    simplified_rax = ctx.simplify(rax, solver=False, llvm=True)

    print("[!] Expression from number:")
    print(rax_ast)

    print("[!] Expression simlified by LLVM:")
    print(simplified_rax)

    rax_concrete_value = ctx.getConcreteRegisterValue(ctx.registers.rax)

    print(f"\n\nConcrete output value from 10: 0x{rax_concrete_value}")

    print()

    M = ctx.liftToLLVM(simplified_rax, fname="fibonacci", optimize=True)

    print("[+] Lifting path to LLVM IR, this will be optimize for precission")
    print()
    print(M)

    Raw = ctx.liftToLLVM(rax_ast, fname="fibonacci", optimize=False)
    print("[+] Lifting to LLVM without optimization:")
    print()
    print(Raw)

def main():
    # Get a triton context
    ctx = TritonContext(ARCH.X86_64)

    # set optimization
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    #ctx.setMode(MODE.CONSTANT_FOLDING, True)
    #ctx.setMode(MODE.AST_OPTIMIZATIONS, True)

    # parse target binary with lief
    binary = lief.parse(TARGET)

    loadBinary(ctx, binary)

    makeRelocation(ctx, binary)

    print("[+] Starting emulation in address: 0x%08X" % (binary.entrypoint))
    emulate(ctx, binary.entrypoint)
    print("[+] Emulation finished")

    print_expression_and_lift(ctx)

if __name__ == "__main__":
    main()
