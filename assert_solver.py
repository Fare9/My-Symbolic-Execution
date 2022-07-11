#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from distutils.command.build_scripts import first_line_re
import sys
from maat import *


first_check = 0x00400b8d
second_check = 0x00400b9c

jnz_address = 0x00400bb1

# first of all let's create the engine and load
# the binary
m = MaatEngine(ARCH.X64, OS.LINUX)
m.load('easy_example', BIN.ELF64)

def assert_checker(m: MaatEngine):
    if m.info.addr == first_check:
        s = Solver()
        print(f"First condition of branch is {m.info.branch.cond}")
        print("inverting it...")
        s.add(m.info.branch.cond.invert())

        if s.check():
            print("A model that satisfies the check was found:")
            model = s.get_model()
            print(f"Value for 'a' can be: {model.get('a')}")
            #print(f"Model: {model.get('b')}")

            print("Applying model to continue running...")
            m.vars.update_from(model)

        return ACTION.CONTINUE

    if m.info.addr == second_check:
        s = Solver()
        print(f"Second condition of branch is {m.info.branch.cond}")
        print("inverting it...")
        s.add(m.info.branch.cond.invert())

        if s.check():
            print("A model that satisfies the check was found:")
            model = s.get_model()
            #print(f"Model: {model.get('a')}")
            print(f"Value for 'b' can be: {model.get('b')}")

            print("Applying model to continue running...")
            m.vars.update_from(model)

        return ACTION.CONTINUE
    # check if we are in the JNZ of the assert:
    if m.info.addr == jnz_address:
        # we create a solver
        s = Solver()
        print(f"Last Condition of branch for assert is {m.info.branch.cond}")
        print("inverting it...")
        s.add(m.info.branch.cond.invert())

        if s.check():
            print("A model that satisfies the check was found:")
            model = s.get_model()
            print(f"Found correct value for 'a': {model.get('a')}")
            print(f"Found correct value for 'b': {model.get('b')}")
        
        return ACTION.HALT

print("As we will run only the function we're interested in")
print("We will apply some configurations first...")


print("Applying symbolic values into RDI")
m.cpu.rdi = Var(64, "a")
print(f"Is RDI symbolic now? = {m.cpu.rdi.is_symbolic()}")

print("Applying symbolic values to RSI")
m.cpu.rsi = Var(64, "b")
print(f"Is RSI symbolic now? = {m.cpu.rsi.is_symbolic()}")

print("Adding hook to branching...")
m.hooks.add(EVENT.BRANCH, WHEN.BEFORE, callbacks=[assert_checker])

print("Running function with assert:")

m.run_from(0x00400b6d)