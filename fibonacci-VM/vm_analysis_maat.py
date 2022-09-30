#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from gc import callbacks
import sys
from maat import *

# True => Debug messages (number of real instruction)
# False => No debug messages (less verbose, no real machine code)
DEBUG = False

vm_file = "./vm_basic.bin"

engine = None
vm_entry_point = 0x115a
vm_exit_point = 0x1261
vm_argument = 10

vm_code_start = 0x4060
vm_code_size = 0x4140 - 0x4060

VM_HANDLERS = set([
    0x129e,
    0x1238,
    0x126d,
    0x11c4,
    0x1262,
    0x11a9,
    0x1245,
    0x11f1,
    0x11e1,
    0x1281,
    0x1226,
])

def instr_before(engine: MaatEngine, n):

    address = engine.info.addr
    vip = engine.cpu.rdx.as_uint()

    if DEBUG:
        print(f"[!] Before instruction at address 0x{address:08X}")

    if address == 0x129e:
        first_value = engine.mem.read(engine.cpu.rcx.as_uint(), 4)
        second_value = engine.mem.read(engine.cpu.rcx.as_uint() - 8, 4)
        print(f"0x{vip:04X}: {second_value} <= {first_value} ", end="")

        if (second_value.as_uint() <= first_value.as_uint()):
            print("(true)")
        else:
            print("(false)")

    elif address == 0x1238:
        ptr = engine.mem.read(engine.cpu.rcx.as_uint(), 8)
        value = engine.mem.read(ptr.as_uint(), 4)
        print(f"0x{vip:04X}: [VM_STACK] = *[*VM_STACK] (0x{ptr.as_uint():08X} => 0x{value.as_uint():x})")

    elif address == 0x126d:
        value_to_check = engine.mem.read(engine.cpu.rdx.as_uint() + 1, 4)
        value_in_r8 = engine.mem.read(engine.cpu.r8, 4)
        print(f"0x{vip:04X}: if [VM_PC+1] (=> {value_to_check}) == 0:\n%spush {engine.cpu.r8} (=> {value_in_r8})" % (' '*12))
        
    elif address == 0x11c4:
        offset = engine.mem.read(engine.cpu.rdx.as_uint() + 1, 4)
        ptr = engine.cpu.rsi + offset
        value_ptr = engine.mem.read(ptr.as_uint(), 4).as_uint()

        print(f"0x{vip:04X}: push 0x{ptr.as_uint():08X} (=> {value_ptr})")

    elif address == 0x11e1:
        value = engine.mem.read(engine.cpu.rdx.as_uint() + 1, 4)

        print(f"0x{vip:04X}: push {value.as_uint()}")

    elif address == 0x1262:
        offset = engine.mem.read(engine.cpu.rdx.as_uint() + 1, 4)
        target = engine.cpu.rdx + offset + 0x1
        print(f"0x{vip:04X}: GOTO 0x{target.as_uint():04X}")

    elif address == 0x11a9:
        first_value = engine.mem.read(engine.cpu.rcx.as_uint(), 4)
        second_value = engine.mem.read(engine.cpu.rcx.as_uint() - 8, 4)

        print(f"0x{vip:04X}: *[VM_STACK] = *[VM_STACK] (=> 0x{first_value.as_uint():X}) + *[VM_STACK-8] (=> 0x{second_value.as_uint():X})")
    
    elif address == 0x1245:
        print(f"0x{vip:04X}: RET")
    
    elif address == 0x11f1:
        first_value = engine.mem.read(engine.cpu.rcx.as_uint(), 4)
        second_value = engine.mem.read(engine.cpu.rcx.as_uint() - 8, 4)

        print(f"0x{vip:04X}: if (*[VM_STACK] (=> 0x{first_value.as_uint():x}) == *[VM_STACK-8] (=> 0x{second_value.as_uint():x})) ", end="")

        if (first_value.as_uint() == second_value.as_uint()):
            print("(true)")
        else:
            print("(false)")
        
        print("%s*[VM_STACK] = 1" % (' '*12))
        print("%selse" % (' '*8))
        print("%s*[VM_STACK] = 0" % (' '*12))
    
    elif address == 0x1281:
        stack_top = engine.mem.read(engine.cpu.rcx.as_uint(), 4)
        offset = engine.mem.read(engine.cpu.rdx.as_uint() + 1, 4)
        target = engine.cpu.rdx + offset + 0x1

        print(f"0x{vip:04X}: if (*[VM_STACK] (=> 0x{stack_top.as_uint():x}) != 0)")

        print(f"%s GOTO 0x{target.as_uint():04X}" % (' ' * 8), end=" ")
        if stack_top.as_uint() != 0:
            print("(taken)")
        else:
            print("(not taken)")

    elif address == 0x1226:
        value = engine.mem.read(engine.cpu.rcx.as_uint(), 4)
        print(f"0x{vip:04X}: POP VAR (=> 0x{value.as_uint():x}")

def instr_after(engine: MaatEngine, n):

    address = engine.info.addr

    if DEBUG:
        print(f"[!] After instruction at address 0x{address:08X}")


def vm_end(engine: MaatEngine, n):
    print(f"[!] End of VM execution returned value = {engine.cpu.rax.as_uint()}")
    return ACTION.HALT

def initialization():
    '''
    Initialization of the MaatEngine, here we will start
    the Symbolix execution engine, and we will load the binary,
    finally we will set the values for the memory and the
    registers.
    '''
    global engine

    print("[+] Initializing the Engine")

    engine = MaatEngine(ARCH.X64, OS.LINUX)

    print("[+] Loading the binary")

    engine.load(vm_file, BIN.ELF64, load_interp=False, base=0x0)

    print("[+] Setting value for RDI")
    engine.cpu.rdi = vm_argument

    print(f"[+] RDI value = {engine.cpu.rdi.as_uint()}")

    print("[+] Setting symbolic values in VM registers...")

    print("[+] Setting RCX as VM_STACK")
    engine.cpu.rcx = Var(64, "VM_STACK")

    print("[+] Setting RDX as VM_PC")
    engine.cpu.rdx = Var(64, "VM_PC")

    print("[+] Setting hooks in the engine...")

    for handler in VM_HANDLERS:
        print(f"\t- Hook in 0x{handler:04X}")
        engine.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=handler, callbacks=[instr_before])
        engine.hooks.add(EVENT.EXEC, WHEN.AFTER, filter=handler, callbacks=[instr_after])

    print("[+] Finally setting a hook at the end of the VM...")
    engine.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=vm_exit_point, callbacks=[vm_end])

    print("[+] Starting the VM with value %d, see you at the end!" % (engine.cpu.rdi.as_uint()))
    engine.run_from(vm_entry_point)



def main():
    initialization()

if __name__ == '__main__':
    main()
