#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys

from maat import *

# create MaatEngine with architecture
# and system
m = MaatEngine(ARCH.X64, OS.LINUX)

# Hook the code execution of the address 0xdeadbeef
# - EVENT.EXEC = when is executed
# - WHEN.BEFORE = execute just before running the address.
# - filter = filter which address
m.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=0xdeadbeef)

# Hook register writes
# EVENT.REG_W = when a register is written
# WHEN.AFTER = execute hook right after write
m.hooks.add(EVENT.REG_W, WHEN.AFTER)

# Hook memory access between 0x1000 and 0x3000
# EVENT.MEM_RW = Execute hook when mem is read or write
# WHEN.BEFORE = Execute right before this happen
# filter = set a range where the hook will be run
m.hooks.add(EVENT.MEM_RW, WHEN.BEFORE, filter=(0x1000, 0x3000))

'''
Possible values for EVENT:

    EVENT.EXEC: executing instruction at given address
    EVENT.REG_R, EVENT.REG_W, EVENT.REG_RW: break when reading/writing register.
    EVENT.MEM_R, EVENT.MEM_W, EVENT.MEM_RW: break when reading/writing memory.
    EVENT.BRANCH: break on branch instruction

Values for second argument:
    WHEN.BEFORE: hook must be triggered before the event.
    WHEN.AFTER: hook must be triggered after the event.

filter must specify a range of memory address, for EXEC a memory address for hooking
and a memory range for monitor the hooking in memory.
'''

# Hooks can have a name, and this can be grouped in a hook group
m.hooks.add(EVENT.REG_R, WHEN.BEFORE, name="hook1", group="reg_hooks")
m.hooks.add(EVENT.REG_W, WHEN.BEFORE, name="hook2", group="reg_hooks")

# Disable hook1
m.hooks.disable("hook1")

# Disable hook1 and hook2 by group
m.hooks.disable_group("reg_hooks")

# Enable hook1
m.hooks.enable("hook1")

# Enable hook1 and hook2
m.hooks.enable_group("reg_hooks")

# we can specify callbacks that can be executed specifying them as
# callbacks, these callbacks can specify an action to take when run
def print_rax_callback(m: MaatEngine):
    print(f"Current RAX: {m.cpu.rax}")
    return ACTION.HALT # stop after the current instruction

m.hooks.add(EVENT.REG_R, WHEN.BEFORE, callbacks=[print_rax_callback])

# if we remember we previously used the info attribute from MaatEngine
# this attribute allowed us to get some information about process, it
# contains useful event-specific information when a callback is called.

def exec_callback(m: MaatEngine):
    print(f"Exec instruction at {m.info.addr}")

def reg_written_callback(m: MaatEngine):
    print(f"Writing register {m.info.reg_access.reg}")
    print(f"Current value {m.info.reg_access.value}")
    print(f"New value {m.info.reg_access.new_value}")

def mem_written_callback(m: MaatEngine):
    print(f"Writing mem at {m.info.mem_access.addr}")
    print(f"Current value {m.mem.read(m.info.mem_access.addr, m.info.mem_access.size)}")
    print(f"New value {m.info.mem_access.value}")

def branch_callback(m: MaatEngine):
    if m.info.branch.taken: # if branch will be taken...
        print(f"Branching to {m.info.branch.target}")
    else:
        print(f"Not branching, next instr at {m.info.branch.next}")