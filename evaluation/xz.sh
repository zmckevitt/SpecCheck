#!/bin/bash

SPEC="/home/zamc2229/cpu2017/benchspec/CPU" # path to SPEC benchmarks
GEM5_PATH="/home/zamc2229/gem5" # path to gem5 project
EXPERIMENT="${GEM5_PATH}/configs/example/se.py" # gem5 experiment location
CFG_LABEL="ML_X86" # label defined in the SPEC .cfg of choice
BENCHMARK="657.xz_s" # full benchmark name
BINARY="xz_s_base" # binary file generated from SPEC
INPUT="cpu2006docs.tar.xz 6643 055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae 1036078272 1111795472 4" # input to binary

echo "running ${CFG_LABEL}.${BENCHMARK}.baseline..."

CWD=$PWD #save current working directory location

cd $SPEC/$BENCHMARK/run/run_base_refspeed_$CFG_LABEL-m64.0000 # go to benchmark run location

# gem5 simulation commands
$GEM5_PATH/build/X86/gem5.opt \
--outdir=$GEM5_PATH/evaluation/run/$BENCHMARK.$CFG_LABEL \
$EXPERIMENT \
--mem-size=8GB \
--cpu-type=DerivO3CPU \
--cpu-clock 2GHz --sys-clock 2GHz \
--l1d_size 32kB --l1d_assoc 8 --l1i_size 32kB \
--l1i_assoc 8 --l2_size 2MB --l2_assoc 16 --l2cache --caches \
--cmd=../../exe/$BINARY.$CFG_LABEL-m64 \
--options="${INPUT}" \
--fast-forward=5000000 \
--maxinsts=1000000 

cd $CWD # return to evaluation folder

echo "finished ${CFG_LABEL}.${BENCHMARK}"
