#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys
from maat import *

# show args!!!!

# we will now show the args received by the program,
# this can be done reading the RSP register.


# MaatEngine(architecture, system)
m = MaatEngine(ARCH.X64, OS.LINUX)

# load binary
m.load("print.bin", BIN.ELF64, args=[b'hello'], load_interp=False)

# when entering _start() we will have argc and argv[] on the stack
argc = m.mem.read(m.cpu.rsp, 8) # read argc (8 bytes) from the stack
argv = m.mem.read_buffer(m.cpu.rsp + 8, argc.as_uint(), 8) # read buffer of 'argc' 8-byte elements

print(f"argc is: {argc}")
print(f"argv is: {argv}")
print(f"argv[0] is: {m.mem.read_str(argv[0])}") # read C string at argv[0]
print(f"argv[1] is: {m.mem.read_str(argv[1])}") # read C string at argv[1]