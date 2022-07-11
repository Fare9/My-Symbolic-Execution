#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys
from maat import *

m = MaatEngine(ARCH.X64, OS.LINUX)


# With Maat we can create symbolic variables
# this will contain a symbolic value instead
# of a concrete one.

# this will be assigned to the registers and
# will hold just an abstract value!
m.cpu.rax = Var(64, "a")
m.cpu.rbx = Var(64, "b")

# we can operate with these values, for example
# printing type
print(type(m.cpu.rax))

# or we can operate with it for creating formulas!
x = (m.cpu.rax + 0x100)*m.cpu.rbx + 2*m.cpu.rax # create a complex expression

print(x)
print(type(x))

# symbolic values variables cannot be called together
# with "as_int()" or "as_uint()", it will raise a
# RuntimeError

# we can concretize a value and associate a concrete
# a value, we have to use the vars attribute from the
# MaatEngine, which is a VarContext

# Set to the symbolic value "a" the value 0x12345678
m.vars.set("a", 0x12345678)

# rax is an abstract concolic value yet
print(m.cpu.rax)
# but if we want to access its value as uint...
# we can specify a context!
print(m.cpu.rax.as_uint(m.vars))

# for CPU registers, the VarContext argument is by default
# m.vars, so we can directly call
print(m.cpu.rax.as_uint())

'''
Summarizing we have next abstract values:

* Concrete values: contain no symbolic variables.
* Symbolic values: contain at least one symbolic variable which doesn't
have a value set in VarContext. They can not be concretized and are
refered as 'fully symbolic'.
* Concolic values (concrete + symbolic): contain at least one symbolic
variable and all variables it contains have a value set in VarContext.
'''

# We can check its type in the next way:
c = Cst(32, 0x1234)

print(c.is_concrete(m.vars)) # True
print(c.is_concolic(m.vars)) # False
print(c.is_symbolic(m.vars)) # False

# "a" is concolic when it has a value in the VarContext
a = Var(64, "a")
m.vars.set("a", 0x12345678)
print(a.is_concolic(m.vars)) # True
print(a.is_symbolic(m.vars)) # False

# "a" becomes symbolic when its value is removed from VarContext
m.vars.remove("a")
print(a.is_concolic(m.vars)) # False
print(a.is_symbolic(m.vars)) # True


# we can do a register concolic in the next way
m.cpu.rax = 0x111 # set a concrete value
m.vars.set("my_rax", m.cpu.rax.as_uint()) # set a value to variable "a"
m.cpu.rax = Var(64, "my_rax") # now rax is "a" which has value 0x111
print(m.cpu.rax)
print(m.cpu.rax.as_uint())
print(f"RAX is concolic? {m.cpu.rax.is_concolic(m.vars)}")
print(f"RAX is symbolic? {m.cpu.rax.is_symbolic(m.vars)}")
print(f"RAX is concrete? {m.cpu.rax.is_concrete(m.vars)}")

# For working with memory, Maat provides a "make_symbolic()" and
# "make_concolic()" helper methods.
m.mem.map(0x0, 0xfff)
# symbolize memory at address 0x100 as array named "buf" of 2
# variables of 4 bytes each
m.mem.make_symbolic(0x100, 2, 4, "buf")
# now read the symbolic variables...
print(m.mem.read(0x100, 4))
print(m.mem.read(0x104, 4))

# We can now make the memory concolic
m.mem.map(0x1000, 0x1fff)
m.mem.write(0x1100, b'whatever') # write concrete data
# we now will make memory address concolic
m.mem.make_concolic(0x1100, 2, 4, "buf2")
print(m.mem.read(0x1100, 4))
print(m.mem.read(0x1104, 4))

# now let's get the values from the concolic values
print(m.vars.get("buf2_0"))
# or in other way
print(m.mem.read(0x1100, 4).as_uint(m.vars))
# or read the whole variable as a buffer
print(m.vars.get_as_buffer("buf2", 4))

# We can generate symbolic buffers with VarContext's
# new_symbolic_buffer(), and new_concolic_buffer() methods.
# Those can be used to pass symbolic program arguments, or
# write symbolic data to filesystem.

# create symbolic buffer of 4 8-bytes values
symbolic_buffer = m.vars.new_symbolic_buffer("x", 4, elem_size=8)

print(symbolic_buffer)

# now we can create a concolic buffer with values [1,2,3,4]
concolic_buffer = m.vars.new_concolic_buffer("y", [1,2,3,4], nb_elems=4, elem_size=8)

# we can get the first value from the array!
print(m.vars.get("y_0"))

# or we can create a buffer with concrete bytes!
print(m.vars.new_concolic_buffer("z", b'foo'))

# and of course obtain its values
print(chr(m.vars.get("z_0")))

# or get value as string
print(m.vars.get_as_str("z"))
