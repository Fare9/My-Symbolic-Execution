#!/bin/bash

seed=$1
input=$2
output=$3

tigress --Verbosity=1 --Seed=$seed --FilePrefix=obf \
      --Transform=InitImplicitFlow \
         --InitImplicitFlowCount=1 \
      --Transform=AntiTaintAnalysis \
          --AntiTaintAnalysisKinds=argv \
          --Functions=main \
      --Transform=Virtualize \
         --VirtualizeDispatch=ifnest \
         --Functions=SECRET \
         --VirtualizeImplicitFlow=PCInit \
         --VirtualizeCopyKinds=counter,bitcopy_unrolled,bitcopy_loop \
      --Transform=Jit \
         --JitFrequency=1\
         --JitImplicitFlow=true \
         --JitDumpOpcodes=0 --JitDumpIntermediate=false \
         --Functions=SECRET \
      --out=$output.c $input.c


