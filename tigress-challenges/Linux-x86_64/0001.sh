#!/bin/bash

seed=$1
input=$2
output=$3
jitter=$4

tigress --Verbosity=1 --Seed=$seed --FilePrefix=obf \
      --Transform=InitEntropy \
         --Functions=main\
      --Transform=InitOpaque \
         --Functions=main --InitOpaqueCount=1 --InitOpaqueStructs=list,array\
      --Transform=Virtualize \
         --VirtualizeMaxDuplicateOps=2 \
         --VirtualizeAddOpaqueToVPC=true \
         --VirtualizeDispatch=direct \
         --VirtualizeOperands=stack,registers \
         --VirtualizeMaxMergeLength=5 --VirtualizeSuperOpsRatio=2.0 \
         --VirtualizeInstructionHandlerSplitCount=2 \
         --Functions=SECRET \
      --out=$output.c $input.c
