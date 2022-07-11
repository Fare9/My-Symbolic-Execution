#!/bin/bash

seed=$1
input=$2
output=$3
jitter=$4

tigress --Verbosity=1 --Seed=$seed --FilePrefix=obf \
      --Transform=InitOpaque \
         --InitOpaqueCount=2 \
         --Functions=main \
      --Transform=InitBranchFuns \
         --InitBranchFunsCount=2 \
         --Functions=main \
      --Transform=AntiTaintAnalysis \
         --Functions=main \
         --AntiTaintAnalysisKinds=argv \
      --Transform=Virtualize \
         --VirtualizeDispatch=switch,direct,indirect,ifnest \
         --VirtualizeImplicitFlow=PCInit \
         --VirtualizeCopyKinds=counter,bitcopy_unrolled,bitcopy_loop \
         --Functions=SECRET \
      --Transform=Virtualize \
         --VirtualizeDispatch=call,switch,direct,indirect,ifnest \
         --Functions=SECRET \
      --Transform=AntiBranchAnalysis \
         --Functions=SECRET \
         --AntiBranchAnalysisKinds=branchFuns \
      --out=$output.c $input.c


