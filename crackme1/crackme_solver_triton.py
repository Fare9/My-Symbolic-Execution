#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from triton import *

import string
import lief
import sys
import os

# Target binary
TARGET="./crackme1"

# Global settings
SYMBOLIC = True
CONCRETE = not SYMBOLIC

# Memory mapping
BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_STACK = 0x9ffffff0
ERRNO      = 0xa0000000


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


def __isoc99_scanf(triton_ctx):
    '''
    Emulate the scanf routine, here we will
    symbolize the buffer we want to set.
    '''
    print("[+] scanf hooked")
    # get rsi where second argument is
    rsi = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.rsi)

    print("Symbolizing the user input in the address: 0x%08X" % (rsi))

    for i in range(8):
        # set first a concrete value (concolic)
        triton_ctx.setConcreteMemoryValue(MemoryAccess(rsi+i, CPUSIZE.BYTE), 61)
        # symbolize the memory address for extracting the expression
        triton_ctx.symbolizeMemory(MemoryAccess(rsi+i, CPUSIZE.BYTE))
    # finally set a 0 value (end of string)
    triton_ctx.setConcreteMemoryValue(MemoryAccess(rsi+8, CPUSIZE.BYTE), 0)

    return (CONCRETE, 1)

def printf(triton_ctx):
    '''
    Emulate the printf function, we will retrieve the message and
    print it
    '''
    print("[+] printf hooked")

    # get address of the string pointer
    rdi = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.rdi)

    # extract the string value
    string_value = getMemoryString(triton_ctx, rdi)

    # just print it, we do not care about other printf stuff now
    print(string_value)
    
    # return the length of that string
    return (CONCRETE, len(string_value))

def strlen(triton_ctx):
    '''
    Emulate strlen, in this case we just return the length 8
    '''
    print("[+] strlen hooked")

    # in this case we are just interested on returning the correct length
    return (CONCRETE, 8)

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


customRelocation = [
    ['__isoc99_scanf', __isoc99_scanf, None],
    ['printf', printf, None],
    ['strlen', strlen, None],
    ['__libc_start_main', libc_start_main, None]
]


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


def emulate(ctx, pc, value_to_check):
    '''
    Emulation method, go over each instruction applying all the
    symbolic execution to registers and memory.

    :param ctx: Triton context to apply symbolic execution.
    :param pc: the program counter value where to start and continue.
    :valut_to_check: value to check once we wants to stop the execution.
    '''
    count = 0

    while pc:
        
        #print("[-] Running instruction at address: 0x%08X" % (pc))
        
        # retrieve the opcodes from the program counter
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)
        
        # create the instruction to emulate
        instruction = Instruction(pc, opcodes)
        ret = ctx.processing(instruction)

        if instruction.getType() == OPCODE.X86.HLT:
            break
            
        if pc == 0x000008a4:
            # here we will apply our model to check the value
            rdx_s = ctx.getRegisterAst(ctx.registers.rdx)

            # This is just for debugging purposes!
            ast = ctx.getAstContext()
            rdx_ast = ast.unroll(rdx_s)
            print(rdx_ast)

            # push the constraint so we can solve
            # the model
            ctx.pushPathConstraint(rdx_s == value_to_check)
            cstr = ctx.getPathPredicate()

            m = ctx.getModel(cstr)

            # once model has been solved, extract the
            # output and put it on a string
            str = [0, 0, 0, 0, 0, 0, 0, 0]
            for k, v in m.items():
                print(f"{k} = {v.getValue()}")
                str[k] = chr(v.getValue())

            return ''.join(str)

        # just for debugging purposes!
        if pc == 0x0000089c:
            rsi = ctx.getConcreteRegisterValue(ctx.registers.rsi)
            print("[+] Transforming buffer in address: 0x%08X" % (rsi))
            
        # Simulate routines
        hookingHandler(ctx)

        # Next
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

        count += 1


def run(triton_ctx, binary, value_to_check):
    '''
    Set fake values for the stack both in RBP and
    in RSP, this will make the code have a stack.
    Then start emulating the binary, for emulating the
    binary we will make Triton to run instruction by instruction
    until finishing in the one we want.
    '''
    # define a fake stack
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.rbp, BASE_STACK)
    triton_ctx.setConcreteRegisterValue(triton_ctx.registers.rsp, BASE_STACK)

    # Emulate binary from the entry point
    print("[+] Starting emulation from entry point 0x%08X" % (binary.entrypoint))
    result = emulate(triton_ctx, binary.entrypoint, value_to_check)
    print("[+] Emulation finished.")

    print(f"[!] String of result: '{result}'")
    

def main():
    # Get a triton context
    ctx = TritonContext(ARCH.X86_64)

    # Set optimizations
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)

    # parse the binary
    binary = lief.parse(TARGET)

    # load the binary now
    loadBinary(ctx, binary)

    # Apply relocations
    makeRelocation(ctx, binary)

    run(ctx, binary, 0x378ed80c535a3630)

if __name__ == '__main__':
    main()