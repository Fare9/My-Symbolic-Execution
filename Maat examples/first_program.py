#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys
# we have to load first all
# the classes from maat
from maat import *


# Maat main object is known as MaatEngine
# with this we will be able to apply execution,
# constraint solving, taking snapshots, etc.

# we will give the architecture and system 
# of the binary
m = MaatEngine(ARCH.X64, OS.LINUX)

# now we will load a simple binary that just prints
# the first character of the first argument

# we specify:
# - the path to the binary
# - the type of the binary
# - and command line
# - load_interp is a little bit special:
#   - True: Maat will try to find interpreter requested by program
#           load it, and symbolically execute interpreter code to load
#           program and dependencies. Ensure binary and dependencies are
#           properly loadded. Drawback is user has to provide binaries
#           for interpreter and all shared libraries.
#   - False: Here Maat will load program and dependencies, and perform
#            relocations. If Maat can find dependencies it will try to
#            emulate them, this is not the best as it can work for libc
#            but become horrible for others.
# More options can be obtained in documentation.
m.load("print.bin", BIN.ELF64, args=[b"hello"], load_interp=False)

# We can run in different ways:
# m.run() # run from current position to the end.
# m.run(100) # run 100 instructions from current position
# m.run_from(0x1234) # run starting at address 0x1234
# m.run_from(0x1234, 100) # same as before but run 100 instructions

# we can enable printing of instructions with next:
# m.settings.log_insts = True

# we can also set register values or check them
# with
# m.cpu.rax = 0x1234 # for setting value
# m.cpu.rax # for printing
# each register is an object of class Value
# which can be concrete or abstract

# we can map memory in the next way:
m.mem.map(0x0, 0xfff, PERM.RW) # map memory from 0 to 0xfff with RW permission

# then we can write to memory in next way:
m.mem.write(0x100, 10, 4) # write value 10 in 4 bytes in address 0x100

# Now to write a whole buffer:
buf = b'I love pineapples\x00'
m.mem.write(0x200, buf, len(buf))

# write current value of rax at address pointed by RSP
# m.mem.write(m.cpu.rsp, m.cpu.rax)

# It's also possible to read from memory
m.mem.write(0x100, 0x12345678, 4)
print(f"Read 4 bytes from address 0x100 = {m.mem.read(0x100, 4)}") # read 4 bytes from address 0x100
print(f"Read 2 bytes from address 0x100 = {m.mem.read(0x100, 2)}") # read 2 bytes from address 0x100

print("Reading a string from 0x200: ")
i = 0
while True:
    c = m.mem.read(0x200 + i, 1)

    if c.as_uint() == 0x00:
        break

    sys.stdout.write("%c" % c.as_uint())
    i += 1

print("")


m.run()

# once it has run we can check information about how it was with:
print(m.info)
# fields can be accessed separately
print(f"value m.info.stop {m.info.stop}")
print(f"value m.info.exit_status {m.info.exit_status}")

print(f"RAX = {m.cpu.rax}")
print(f"RSP = {m.cpu.rsp}")

# creating Value objects

# constants
x = Cst(32, 1) # value 1 in 32 bits
y = Cst(64, -78) # value -78 in 64 bits
z = Cst(27, 0x45) # value 0x45 in 27 bits

print(f"x.size = {x.size}, x = {x}")

# we can combine values from Cst objects and
# register Value objects, so we can see the
# results:
rbx = m.cpu.rbx
print(f"rbx = {rbx}")

x = rbx + 0xff
print(f"x = rbx + 0xff -> {x}")

# all the basic operations are implemented
x = Cst(32, 0xcafe)
y = Cst(32, 0xbabe)

print(f"x+y = {x+y}")
print(f"x-y = {x-y}")
print(f"x*y = {x*y}")
print(f"x/y = {x/y}")
print(f"x&y = {x&y}")
print(f"x|y = {x|y}")
print(f"x^y = {x^y}")
print(f"x>>y = {x>>y}")
print(f"x<<y = {x<<y}")
print(f"x%y = {x%y}")
print(f"-x = {-x}") # unary minus
print(f"~x = {~x}") # logical NOT

print(f"x<10:2> = {Extract(x,10,2)}")
print(f"concat x+y = {Concat(x,y)}")

# finally Values can be obtained as common
# python ints or uints
x = Cst(32, -67)

print(f"int x = {x.as_int()}")
print(f"uint x = {x.as_uint()}")