#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys
from maat import *

# first of all let's create the engine and load
# the binary
m = MaatEngine(ARCH.X64, OS.LINUX)
m.load('crackme1', BIN.ELF64, base=0x04000000, libdirs=["./"])

# Fill stdin with 8 bytes of concolic input
# On a single-processs linux environment, stdin handle is 
# commonly always 0
stdin = m.env.fs.get_fa_by_handle(0)
# now we create the 8 bytes concolic buffer!
buf = m.vars.new_concolic_buffer(
    "input", # name of buffer
    b'aaaaaaaa', # content
    nb_elems=8, # number of elements
    elem_size=1, # size of each
    trailing_value=ord('\n') # concrete new line at the end of the input
)

# write the buffer into stdin
stdin.write_buffer(buf)

def branch_serial_callback(m: MaatEngine, n):
    # check that the branch we are using
    # is the one of the check
    if m.info.addr == 0x040008b1:
        # now we create a solver, and we are going
        # to add the invert of the path it will take
        # as constraint
        s = Solver()
        print(f"Condition of branch is {m.info.branch.cond}")
        print("inverting it...")
        s.add(m.info.branch.cond.invert())
        # check if there's a model that satisfies
        # our inverted branch from the symbolic
        # concolic variables.
        print(f"Is jump taken with our buffer 'aaaaaaaa'? = {m.info.branch.taken}")
        if m.info.branch.taken:
            print("in our execution crackme is not solved...")
        
        if s.check():
            model = s.get_model()
            print(f"Found serial: {model.get_as_str('input')}")
        else:
            print("Failed to find serial")

        return ACTION.HALT

m.hooks.add(EVENT.BRANCH, WHEN.BEFORE, callbacks=[branch_serial_callback])

print("Let's going to run crackme and find a solution that")
print("solves the constraint on the jump!")

m.run()