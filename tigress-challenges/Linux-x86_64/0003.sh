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
         --Functions=SECRET \
      --Transform=EncodeArithmetic \
         --Functions=SECRET \
      --Transform=Split \
         --Functions=SECRET \
         --SplitCount=50 \
         --SplitName=SPLIT \
      --Transform=Merge \
         --Functions=%30  --Exclude=main \
         --MergeName=MERGE1\
         --MergeFlatten=true --MergeFlattenDispatch=switch \
      --Transform=Merge \
         --Functions=%30  --Exclude=main \
         --MergeName=MERGE2 \
         --MergeFlatten=true --MergeFlattenDispatch=goto \
      --Transform=Merge \
         --Functions=%30  --Exclude=main \
         --MergeName=MERGE3 \
         --MergeFlatten=true --MergeFlattenDispatch=indirect \
      --Transform=AntiAliasAnalysis \
         --Functions=* \
      --out=$output.c $input.c


