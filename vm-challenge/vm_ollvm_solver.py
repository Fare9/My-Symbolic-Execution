#!/usr/bin/env python3
#-*- coding: utf-8 -*-

'''
Solution for VM O-LLVM based by Mr.Phrazer
We will base our solution in the one done
by Triton, but this time using Maat. It will
be useful to learn how to solve this kind of
VM based obfuscations!
'''


from gc import callbacks
import sys
from maat import *


# Path to binary
BINARY_PATH = "./ollvm"
# Path to next libs:
'''
linux-vdso.so.1 
libstdc++.so.6
libm.so.6
libgcc_s.so.1
libc.so.6
'''
PATH_TO_LIBS = ""
#ADDR_SAFE_STRTOUL = 0x004007b0
ADDR_SAFE_STRTOUL = 0x00400816
END_ADDR = 0x004008da



engine = MaatEngine(ARCH.X64, OS.LINUX)

def load_the_binary():
    '''
    Load the binary in Maat engine, so we
    can run it symbolically.
    '''
    global engine
    global BINARY_PATH
    global PATH_TO_LIBS

    engine.load(BINARY_PATH, BIN.ELF64, args=[b'0x41414141'], libdirs=[PATH_TO_LIBS])


def hook_safe_strtoul(m: MaatEngine):
    '''
    Hook to the created strtoul safe function
    here we will set the RAX value
    '''

    print("[!] Hooked the safe strtoul call")

    print(f"[+] Setting the RAX value to a concolic value: 0x41414141")

    m.cpu.rax = 0x41414141
    m.vars.set("user_value", m.cpu.rax.as_uint())
    m.cpu.rax = Var(64, "user_value")

    print(f"[+] RAX Concolic Name: {m.cpu.rax}")
    print(f"[+] RAX Concolic Value: 0x{m.cpu.rax.as_uint():08X}")
    print(f"[+] RAX is concolic? {m.cpu.rax.is_concolic(m.vars)}")

    '''
    print("[!] Restoring RIP and RSP as if we have done the call")

    ret_rip = m.mem.read(m.cpu.rsp.as_uint(), 8)
    
    print(f"[+] Returning to address: {ret_rip}")
    m.cpu.rip = ret_rip
    m.cpu.rsp = m.cpu.rsp.as_uint() + 8
    '''
    print("[!] End of hook in strtoul")
    ACTION.CONTINUE

def hook_end_addr(m: MaatEngine):
    '''
    Hook the last instruction to run, and apply
    the solver check.
    '''
    print("[!] Start hook on end_addr")

    s = Solver()

    rsi = m.cpu.rsi

    print(f"RSI: {rsi}")

    s.add(rsi == 0x875cd4f2e18f8fc4)

    if s.check():
        model = s.get_model()
        print(f"Found serial: {model}")
    else:
        print("Failed to find serial")

    return ACTION.HALT

def exec_callback(m: MaatEngine):
    print(f"Exec instruction at {m.info.addr:08X}")

def check(m: MaatEngine):
    print("[+] Some check:")

    rbp = m.cpu.rbp

    print(f"[+] RBP = {rbp}")

    print(f"[+] RBP is concolic? {m.cpu.rbp.is_concolic(m.vars)}")

    s = Solver()

    s.add(rbp == 0xb224eb11a3788e3b)

    if s.check():
        model = s.get_model()
        print(f"Found serial: {model}")
    else:
        print("Failed to find serial")

    #return ACTION.HALT

def initialization():
    global engine
    global ADDR_SAFE_STRTOUL
    global END_ADDR

    print(f"[!] Initializing the engine to run the program {BINARY_PATH}")

    print("[+] Loading the binary in engine")

    load_the_binary()

    print(f"[+] Hooking the SAFE_STRTOUL: {ADDR_SAFE_STRTOUL:08X}")
    engine.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=ADDR_SAFE_STRTOUL, callbacks=[hook_safe_strtoul])

    print(f"[+] Hooking the last address to execute: {END_ADDR:08X}")
    engine.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=END_ADDR, callbacks=[hook_end_addr])

    engine.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=0x00463b12, callbacks=[check])

    engine.hooks.add(EVENT.EXEC, WHEN.BEFORE, callbacks=[exec_callback])

    engine.cpu.rax = 0x41414141
    engine.vars.set("user_value", engine.cpu.rax.as_uint())
    engine.cpu.rax = Var(64, "user_value")

    print("[!] Starting running the binary!")
    engine.run_from(0x00400899)

def main():
    initialization()

if __name__ == '__main__':
    main()