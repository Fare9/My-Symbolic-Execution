#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import sys
from maat import *

m = MaatEngine(ARCH.X64, OS.LINUX)

# we create a symbolic variable...
a = Var(64, "a")

# now we could apply constraints
a == 100
a != 100
a < 100
a <= 100
a > 100
a >= 100

# we could also combine them...
(a == 100) & (a > 120)
(a < 100) | (a > 30)

# we can invert a constraint in two ways:
~(a == 100) # a != 100
(a == 100).invert()

# We can apply constraint solving which will
# try to solve all the constraints with symbolic
# variables and get a model where a solution or
# concrete value for each symbolic variable is found.

# first create a solver object
solver = Solver()
# now create symbolic variables
a = Var(64, "a")
b = Var(64, "b")
c = Var(64, "c")

solver.add(a > b)
solver.add(b == c)
solver.add(c == 0x42)

# now we have to check if there's a model
# that solves our constraints
if not solver.check():
    print("No model has been found")
    sys.exit(1)

model = solver.get_model()
print(model)
# now we can apply the model to our VarContext
m.vars.update_from(model)
print(m.vars)

# reset the solver to flush constraints out
solver.reset()