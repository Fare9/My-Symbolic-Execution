#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from triton import *

import string
import time
import lief

# Target binary
TARGET = "./challenge"

# Global settings
SYMBOLIC = True
CONCRETE = not SYMBOLIC

# Memory mapping
BASE_PLT = 0x10000000
BASE_ARGV = 0x20000000
BASE_STACK = 0x9ffffff0
ERRNO = 0xa0000000

# Values to do the symbolic execution

MEM_ADDRESS_BUFFER = None

# address where we can add the constraints of the conditions
FIRST_CONDITIONAL = 0x000012bf
SECOND_CONDITIONAL = 0x000012e0
THIRD_CONDITIONAL = 0x000013c5
FOURTH_CONDITIONAL = 0x00001447
FIFTH_CONDITIONAL = 0x00001492

# address of the loops to bypass
FIRST_LOOP = 0x000013ce
SECOND_LOOP = 0x00001452

"""
Hooks and utilities for emulation
"""
def getMemoryString(ctx, addr):
    '''
    Function to extract a python string from
    a memory address, we will read a c-style
    string, reading the concrete memory value.

    :param ctx: Triton context with utilities
    :param addr: address with the string.
    '''
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr+index):
        c = chr(ctx.getConcreteMemoryValue(addr+index))
        if c not in string.printable:
            c = ""
        s += c
        index += 1

    return s


def strncpy(triton_ctx):
    '''
    Emulate a strncpy and apply the symbolization
    to the destination buffer.
    '''
    global MEM_ADDRESS_BUFFER

    print("[+] strncpy hooked")
    # get rdi the first argument to be hooked
    rdi = triton_ctx.getConcreteRegisterValue(triton_ctx.registers.rdi)

    print("Symbolizing the user input in the address 0x%08X" % rdi)

    # save the value
    MEM_ADDRESS_BUFFER = rdi

    triton_ctx.setConcreteMemoryAreaValue(rdi, b"?"*0x17+b'\x00')

    for i in range(0x18):
        memory_byte = MemoryAccess(rdi+i, CPUSIZE.BYTE)
        # symbolize the memory address for extracting the expression
        triton_ctx.symbolizeMemory(memory_byte)

    # finally set a 0 value (end of string)
    # triton_ctx.setConcreteMemoryValue(MemoryAccess(rdi+0x18, CPUSIZE.BYTE), 0)
    # return the strncpy value as a concrete value
    return (CONCRETE, 0x18)


def libc_start_main(ctx):
    '''
    Emulation of libc start, here we will set the
    arguments giving them an address in memory and
    copying the values into that memory.
    '''
    print('[+] __libc_start_main hooked')

    # Get arguments
    main = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    # Push the return value to jump into the main() function
    ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(
        ctx.registers.rsp)-CPUSIZE.QWORD)

    # set as return value the address of main
    # avoid all the libc stuff
    ret2main = MemoryAccess(ctx.getConcreteRegisterValue(
        ctx.registers.rsp), CPUSIZE.QWORD)
    ctx.setConcreteMemoryValue(ret2main, main)

    # Setup argc / argv
    ctx.concretizeRegister(ctx.registers.rdi)
    ctx.concretizeRegister(ctx.registers.rsi)

    # here write all the needed arguments
    argvs = [
        bytes(TARGET.encode('utf-8')),  # argv[0]
        b'A'*0x18 + b'\00'
    ]

    # Define argc / argv
    base = BASE_ARGV
    addrs = list()

    # create the arguments
    index = 0
    for argv in argvs:
        addrs.append(base)
        ctx.setConcreteMemoryAreaValue(base, argv+b'\x00')
        base += len(argv)+1
        print('[+] argv[%d] = %s' % (index, argv))
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


# this structure will be useful during emulation
# whenever the emulation jumps to any of the functions
# from the first field, use the second fields as hook.
customRelocation = [
    ['strncpy', strncpy, None],
    ['__libc_start_main', libc_start_main, None]
]

"""
Code for loading the binary with lief
"""


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
        size = phdr.physical_size
        vaddr = phdr.virtual_address
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
                print('[+] Init PLT for: %s' % (symbolName))
                ctx.setConcreteMemoryValue(MemoryAccess(
                    symbolRelo, CPUSIZE.QWORD), crel[2])
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
            ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(
                ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))
            # Hijack RIP to skip the call
            ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)
            # Restore RSP (simulate the ret)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(
                ctx.registers.rsp)+CPUSIZE.QWORD)
    return


def getVarSyntax(ctx):
    '''
    Retrieve all the declared symbolic variables
    and generatae them as a string like the next:

    (declare-fun SymVar_0 () (_ BitVec 8))

    :param ctx: triton context for using utilities
    '''
    s = str()
    ast = ctx.getAstContext()
    for k, v in list(ctx.getSymbolicVariables().items()):
        s += str(ast.declare(ast.variable(v))) + '\n'
    return s


def getSSA(ctx, expr):
    '''
    Get an SSA version of the expression given as parameter
    this will generate all the expressions in an IR form
    with SSA form.

    :param ctx: triton context for using utilities
    :param expr: expression to retrieve its SSA form
    '''
    s = str()
    # current AST of the program
    ast = ctx.getAstContext()
    # generate an IR in SSA from the expression
    ssa = ctx.sliceExpressions(expr)
    for k, v in sorted(ssa.items())[:-1]:
        s += str(v) + '\n'
    s += str(ast.assert_(expr.getAst())) + '\n'
    return s


def myExternalSolver(ctx, node, addr=None, debug=False):
    """
    The particularity of this sample is that we use an external solver to solve
    queries instead of using the internal Triton's solver (even if in both cases
    it uses z3). The point here is to show that Triton can provide generic smt2
    outputs and theses outputs can be send to external solvers and get back model
    which then are sent to Triton.
    """
    import z3
    expr = ctx.newSymbolicExpression(node, "Custom for Solver")
    varSyntax = getVarSyntax(ctx)
    ssa = getSSA(ctx, expr)


    smtFormat = '(set-logic QF_BV) %s %s (check-sat) (get-model)' % (
        varSyntax, ssa)
    
    if debug:
        print(smtFormat)

    c = z3.Context()
    s = z3.Solver(ctx=c)
    s.add(z3.parse_smt2_string(smtFormat, ctx=c))
    if addr:
        print('[+] Solving condition at %#x' % (addr))
    if s.check() == z3.sat:
        ret = dict()
        model = s.model()
        for x in model:
            if not "ref" in str(x):
                ret.update(
                    {int(str(x).split('_')[1], 10): int(str(model[x]), 10)})
            else:
                continue
        return ret
    else:
        print('[-] unsat :(')
        sys.exit(-1)
    return


def emulate(ctx, pc):
    '''
    Emulation method, go over each instruction applying all the
    symbolic execution to registers and memory.

    :param ctx: Triton context to apply symbolic execution.
    :param pc: the program counter value where to start and continue.
    :valut_to_check: value to check once we wants to stop the execution.
    '''

    # This structure will be used for applying the constraints in certain
    # addresses from the program, give a register to apply the constraint
    # and the value used during the comparison.
    check_register_value = [
        FIRST_CONDITIONAL,
        SECOND_CONDITIONAL,
        THIRD_CONDITIONAL,
        FOURTH_CONDITIONAL,
        FIFTH_CONDITIONAL,
    ]

    # Structure used to jump over the decryption loops which are
    # not useful for the analysis
    loop_address_dest = [
        [FIRST_LOOP, 0x0000141d],
        [SECOND_LOOP, 0x00001483]
    ]

    # emulation loop
    while pc:

        # print("[-] Running instruction at address: 0x%08X" % (pc))
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)
        instruction = Instruction(pc, opcodes)
        
        # Code for stepping out code that is not necessary
        # to be executed

        # call a not implemented function, jump over it
        # adding the length of a call instruction
        if pc in [0x0000124a, 0x00001254, 0x0000126d]:
            print("Not emulated function, continue")
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
            pc += 5
            continue
        # avoid decryption loops
        avoid_loop = False
        for val in loop_address_dest:
            if pc == val[0]:
                print("Decryption loop address 0x%08X, moving to 0x%08X" %
                      (val[0], val[1]))
                pc = val[1]
                avoid_loop = True
                break

        if avoid_loop:
            continue

        # process the instruction
        ret = ctx.processing(instruction)
        # if HALT, finish the execution
        if instruction.getType() == OPCODE.X86.HLT:
            break

        # conditions
        if pc in check_register_value:
            print("Checking at address: 0x%08X" % (val[0]))
            zf = ctx.getSymbolicRegister(ctx.registers.zf).getAst()
            ast = ctx.getAstContext()
            pco = ctx.getPathPredicate()
            model = myExternalSolver(ctx, zf == 1, pc)
            for k, v in list(model.items()):
                ctx.setConcreteVariableValue(ctx.getSymbolicVariable(k), v)

        # solve the equation and retrieve the whole Password
        if pc == 0x0000149b:
            # in this case provide True for solving the expression
            ast = ctx.getAstContext()
            pco = ctx.getPathPredicate()
            print("Checking final at address: 0x%08X" % (pc))
            mod = myExternalSolver(ctx, ast.land(
                [pco] +
                [ast.variable(ctx.getSymbolicVariable(x)) >= 0x20 for x in range(0, 0x18)] +
                [ast.variable(ctx.getSymbolicVariable(x)) <= 0x7e for x in range(0, 0x18)] +
                [ast.variable(ctx.getSymbolicVariable(x)) !=
                 0x00 for x in range(0, 0x18)]
            ))
            serial = str()
            for k, v in sorted(mod.items()):
                serial += chr(v)
            print("PASSWORD = %s" % (serial))
            return

        # apply one of the handlers that are not provided by
        # Triton
        hookingHandler(ctx)

        # Next
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)


def run(triton_ctx, binary):
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
    print("[+] Starting emulation from entry point 0x%08X" %
          (binary.entrypoint))
    d1 = time.time()
    emulate(triton_ctx, binary.entrypoint)
    d2 = time.time()
    print("[+] Emulation finished.")
    print("Time emulation: %.2f milliseconds" % ((d2-d1)*1000))


def main():
    d1 = time.time()
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

    run(ctx, binary)
    d2 = time.time()
    print("Time full analysis: %.2f milliseconds" % ((d2-d1)*1000))


if __name__ == "__main__":
    main()
