#!/bin/bash

seed=$1
input=$2
output=$3
jitter=$4

tigress --Verbosity=1 --Seed=$seed --FilePrefix=obf \
      --Transform=Virtualize \
         --Functions=SECRET --VirtualizeDispatch=? --VirtualizeOperands=stack \
      --out=$output.c $input.c
