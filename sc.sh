#!/bin/bash

args=("$@")
argc=("$#")
if [ $argc -lt 2 ]
then
    echo "Use: bash sc.sh <stats-file> <path-to-binary>"
    exit
fi
EXPERIMENT="${GEM5_PATH}/configs/example/se.py" # gem5 experiment location
STATFILE=${args[0]}

# gem5 simulation commands
$GEM5_PATH/build/X86/gem5.opt \
--debug-flags=SpecCheck \
--stats-file=$STATFILE \
$EXPERIMENT \
--indirect-bp-type=SimpleIndirectPredictor \
--mem-size=8GB \
--cpu-type=DerivO3CPU \
--cpu-clock 2GHz --sys-clock 2GHz \
--l1d_size 32kB --l1d_assoc 8 --l1i_size 32kB \
--l1i_assoc 8 --l2_size 256kB --l2_assoc 16 --l2cache --caches \
--cmd=${args[1]} \
--maxinsts=150000000

OUTFILE="$GEM5_PATH/m5out/$STATFILE.scout"
mv $GEM5_PATH/m5out/SpecCheck.out $OUTFILE
