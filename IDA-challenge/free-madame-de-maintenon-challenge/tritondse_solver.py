#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys
from triton import Instruction, MemoryAccess, CPUSIZE
from tritondse import Program
from tritondse import SymbolicExecutor, Config, Seed, CompositeData, SolverStatus
from tritondse import ProcessState, CoverageStrategy, SeedFormat, SymbolicExplorator

# Target binary
TARGET="./challenge"

# global value with loaded program
p = None

# addresses with the conditional jumps
FIRST_CONDITIONAL = 0x000012c4
SECOND_CONDITIONAL = 0x000012e5
THIRD_CONDITIONAL = 0x000013c8
FOURTH_CONDITIONAL = 0x0000144c
FIFTH_CONDITIONAL = 0x00001492

# address with the decryption loops for
# moving out from them
FIRST_LOOP = 0x000013ce
SECOND_LOOP = 0x00001452
# helper structure to jump over loops
loop_address_dest = [
    [FIRST_LOOP, 0x0000141d],
    [SECOND_LOOP, 0x00001483]
]

MEM_ADDRESS = None

def skip(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
    '''
    Function run post execution of the instructions, here
    we will skip some instructions and will 
    '''
    pc = inst.getAddress()
    if pc in [0x0000124a, 0x00001254, 0x0000126d]: # useless calls
        print("[+] Not emulated function, continue")
        # restore rip to a correct one
        pstate.write_register(pstate.registers.rip, pc + inst.getSize())
        # fix rsp
        rsp = pstate.read_register(pstate.registers.rsp)
        pstate.write_register(pstate.registers.rsp, rsp+8)
        return
    
    if pc == 0x000012a0: # post strncpy
        valid_characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
        min_value = ord(min(valid_characters))
        max_value = ord(max(valid_characters))
        print("[+] strncpy adding constraints to symbolized memory")
        # apply the constraint to the AST of each byte
        for i in range(0x18):
            sym_mem = pstate.read_symbolic_memory_byte(MEM_ADDRESS+i)
            pstate.push_constraint(sym_mem.getAst() >= min_value)
            pstate.push_constraint(sym_mem.getAst() <= max_value)
    
    for value in loop_address_dest: # for stepping out the loops
        if pc == value[0]:
            print("[+] Found call to decryption loop, skipping")
            pstate.write_register(pstate.registers.rip, value[1])
            return
    



def trace_inst(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
    '''
    Function executed right before running an instruction
    it is used to save some values, and apply the constraints
    in the execution.
    '''
    global MEM_ADDRESS

    pc = pstate.read_register(pstate.registers.rip)
    # structure to apply constraints in the moment of the
    # jump execution
    check_register_value = [
        [FIRST_CONDITIONAL, pstate.registers.eax, 0x1cd4], # 0x000012bf
        [SECOND_CONDITIONAL, pstate.registers.eax, 0xd899], # 0x000012e0
        [THIRD_CONDITIONAL, pstate.registers.rdx, 0xa04233a475d1b72], # 0x000013c5
        [FOURTH_CONDITIONAL, pstate.registers.eax, 0x4b5469c], # 0x00001447
    ]

    if pc == 0x000012a0: # call to strncpy
        rsi = pstate.read_register(pstate.registers.rsi)
        print("[+] Strncpy getting source value: 0x%08X" % (rsi))
        # save address of argv
        MEM_ADDRESS = rsi
    
    for value in check_register_value:
        # go over the jumps of each check
        # and apply the constraint with the used
        # register.
        if pc == value[0]:
            print("[-] Found jump instruction, skipping it")
            sym_reg = pstate.read_symbolic_register(value[1])
            pstate.push_constraint(sym_reg.getAst() == value[2])
            # to make sure the comparison always match
            pstate.write_register(pstate.registers.zf, 1)
    # Last constraint and solution of the system
    if pc == FIFTH_CONDITIONAL:
        print("[!] Got final instruction!")
        sym_r8 = pstate.read_symbolic_register(pstate.registers.r8)
        sym_rax = pstate.read_symbolic_register(pstate.registers.rax)
        status, model = pstate.solve(sym_r8.getAst() == sym_rax.getAst())

        # If formula is SAT retrieve input values
        if status == SolverStatus.SAT:
            # Retrieve value of the input variable involved in the cl value here (shall be only one here)
            sym_mem = pstate.read_symbolic_memory_bytes(MEM_ADDRESS, 0x18)
            var_values = pstate.get_expression_variable_values_model(sym_mem, model)
            key_values = {}
            for var, value in var_values.items():
                key_values[var.getId()] = value
            
            flag = ""
            for k in sorted(key_values.keys()):
                v = key_values[k]
                flag += chr(v)
            print("\n\n------------------------------------------")
            print(f"Flag={flag}")
            print("------------------------------------------\n\n")
            sys.exit(0)
        else:
            print(status.name)
        
def main():
    '''
    Main function from the program here we will load the binary
    and then we will call the rest of the functionality
    '''
    global p

    # load the target into the engine
    p = Program(TARGET)

    # now generate the first seed values
    config = Config(coverage_strategy=CoverageStrategy.PATH, debug=True,
                pipe_stdout=True, seed_format=SeedFormat.COMPOSITE)
    seed = Seed(CompositeData(argv=[b"./challenge", b"A"*0x18]))

    # create a symbolic explorator to go
    # symbolically over the program
    executor = SymbolicExecutor(config, seed)
    executor.load(p)
    
    # set the callbacks for pre and post instruction
    executor.callback_manager.register_pre_instruction_callback(trace_inst)
    executor.callback_manager.register_post_instruction_callback(skip)

    executor.run()



if __name__ == '__main__':
    main()