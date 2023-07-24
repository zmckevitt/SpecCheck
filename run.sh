#!/bin/bash

args=("$@")
argc=("$#")
if [ $argc -lt 2 ]
then
    echo "Use: bash sc.sh <stats-file> <path-to-binary>"
    exit
fi
GEM5_PATH="/home/zamc2229/gem_sc" # path to gem5 project
EXPERIMENT="${GEM5_PATH}/configs/example/se.py" # gem5 experiment location

# gem5 simulation commands
$GEM5_PATH/build/X86/gem5.opt \
--stats-file=${args[0]} \
$EXPERIMENT \
--mem-size=8GB \
--cpu-type=DerivO3CPU \
--cpu-clock 2GHz --sys-clock 2GHz \
--l1d_size 32kB --l1d_assoc 8 --l1i_size 32kB \
--l1i_assoc 8 --l2_size 2MB --l2_assoc 16 --l2cache --caches \
--cmd=${args[1]} \
--fast-forward=100000000 \
--maxinsts=150000000
