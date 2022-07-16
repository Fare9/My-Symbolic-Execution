#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from dis import Instruction
from pickletools import optimize
from triton import *

import string
import lief
import sys
import os

DEBUG=True
output_file="tigress-0000-1-instructions.txt"
output_f = None

if DEBUG:
    output_f = open(output_file, 'w')

LOG_INSTRUCTION_VM = False

# Target binary
TARGET=os.path.join(os.path.dirname(__file__), "../../tigress-challenges/Linux-x86_64/0000/challenge-1")

# Global settings
SYMBOLIC = True
CONCRETE = not SYMBOLIC

# Memory mapping
BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_STACK = 0x9ffffff0
ERRNO      = 0xa0000000


#######################################################################
# emulated functions, write here those you want to emulate! ###########
#######################################################################


def libc_start_main(ctx):
    '''
    Hook for libc start function, we will always
    use this function if libc is involved.
    '''
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
        b'test'
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

def strtoul(ctx):
    '''
    Emulate the strtoul, as we will not really use
    much of what strtoul does, we will just return
    a symbolic value.
    '''
    print("[+] Hooked strtoul")
    return (SYMBOLIC, 0x4141414141414141)

#######################################################################
# Useful Functions always present! ####################################
#######################################################################

customRelocation = [
    ['__libc_start_main', libc_start_main, None],
    ['strtoul', strtoul, None]
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

def emulate(ctx, pc):
    '''
    Emulation method, here we will go instruction by instruction,
    and finally we will try to lift and simplify methods.
    '''
    global LOG_INSTRUCTION_VM
    global DEBUG
    global output_f

    run_handlers = 0

    while pc:
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

        # create the instruction to emulate
        instruction = Instruction(pc, opcodes)
        ctx.processing(instruction)

        if pc == 0x004005f4:
            LOG_INSTRUCTION_VM = True
        
        if pc == 0x00400d8a:
            LOG_INSTRUCTION_VM = False

        if DEBUG:
            if LOG_INSTRUCTION_VM:
                output_f.write(str(instruction) + '\n')

                

        # stop if halt executed
        # or in case we reached the address
        # where value was calculated!
        if instruction.getType() == OPCODE.X86.HLT or pc == 0x00400d9d:
            break

        if LOG_INSTRUCTION_VM:
            if instruction.getDisassembly().lower() == "jmp rax":
                rax_value = ctx.getConcreteRegisterValue(ctx.registers.rax)
                print("[+] Handler address to run: 0x%08X" % (rax_value))
                run_handlers += 1
            
        hookingHandler(ctx)

        # Next
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    
    print("[+] Number of run handlers: %d" % (run_handlers))

def print_expression_and_lift(ctx):
    '''
    Method to print the expression from the number,
    and also lift the path followed by the program,
    we can try to apply optimizations to that path.
    '''
    rax = ctx.getRegisterAst(ctx.registers.rax)
    ast = ctx.getAstContext()
    rax_ast = ast.unroll(rax)

    simplified_rax = ctx.simplify(rax, solver=False, llvm=True)

    print()
    print()

    print("[!] Expression from number:")
    print(rax_ast)

    print("[!] Expression simplified with LLVM:")
    print(simplified_rax)

    rax_concrete_value = ctx.getConcreteRegisterValue(ctx.registers.rax)

    print("\n\nConcrete output value from 0x4141414141414141: 0x%08X\n\n" % (rax_concrete_value))

    print()
    
    M = ctx.liftToLLVM(rax, fname="tigress_analytica", optimize=True)
    print("[+] Lifting path to LLVM IR, this will be optimize for precission")
    print()
    print(M)

    print()

    R = ctx.liftToLLVM(rax, fname="tigress_analytica_obf", optimize=False)
    print("[+] Lifting path to LLVM IR, this will not be optimized")
    print()
    print(R)

def main():
    global output_f

    # Get a triton context
    ctx = TritonContext(ARCH.X86_64)

    # set optimization
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)

    # parse target binary with lief
    binary = lief.parse(TARGET)

    loadBinary(ctx, binary)

    makeRelocation(ctx, binary)

    print("[+] Starting emulation in address: 0x%08X" % (binary.entrypoint))
    emulate(ctx, binary.entrypoint)
    print("[+] Emulation finished")

    print_expression_and_lift(ctx)

    if DEBUG:
        output_f.close()

if __name__ == "__main__":
    main()
    