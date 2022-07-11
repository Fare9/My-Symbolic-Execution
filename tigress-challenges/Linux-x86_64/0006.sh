#!/bin/bash

seed=$1
input=$2
output=$3

tigress --Verbosity=1 --Seed=$seed --FilePrefix=obf \
      --Transform=InitImplicitFlow \
         --InitImplicitFlowCount=1 \
      --Transform=Jit \
         --JitFrequency=1\
         --JitImplicitFlow=false \
         --Functions=SECRET \
      --Transform=Jit \
         --JitFrequency=1\
         --JitImplicitFlow=true \
         --Functions=SECRET \
      --out=$output.c $input.c


