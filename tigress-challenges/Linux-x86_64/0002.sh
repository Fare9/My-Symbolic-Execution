#!/bin/bash

seed=$1
input=$2
output=$3
jitter=$4

tigress --Verbosity=1 --Seed=$seed --FilePrefix=obf \
      --Transform=InitEntropy \
         --Functions=main\
      --Transform=InitImplicitFlow \
         --InitImplicitFlowCount=2 \
      --Transform=Virtualize \
         --VirtualizeNumberOfBogusFuns=1 \
         --VirtualizeAddOpaqueToBogusFuns=false\
         --VirtualizeBogusFunsGenerateOutput=false\
         --VirtualizeImplicitFlow=PCInit \
         --Functions=SECRET \
      --out=$output.c $input.c
