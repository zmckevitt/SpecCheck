# SpecCheck

[![DOI](https://zenodo.org/badge/545755894.svg)](https://zenodo.org/badge/latestdoi/545755894)

This repository contains a fork of gem5 with SpecCheck implementation. SpecCheck is a debugging module for O3CPUs to determine the presence of potential transient execution vulnerabilities.

## Building

To build SpecCheck gem5, first clone the repository and checkout the ```SpecCheckPACT``` branch:

```
git clone https://github.com/zmckevitt/gem5.git
cd gem5/
git checkout SpecCheckPACT
```

Next, ensure that your system has scons:

```
sudo apt install scons
```

And lastly build the x86 gem5 model:

```
scons build/X86/gem5.opt -j$(nproc)
```

## Running

The ```pocs/``` directory contains proof of concepts for Spectre variant 1 (Pattern History Table), variant 2 (Branch Target Buffer), variant 3 (Retun Stack Buffer), and variant 4 (Store to Load Forwarding). Each proof of concept was also precompiled on x86 Ubuntu 20.04 and statically linked, and these binaries can be found in ```pocs/precompiled/```.

While in the gem5 directory, save the current working directory to an environment variable to be used in runner scripts:

```
export GEM5_PATH=$(pwd)
```

To run gem5 with SpecCheck enabled, use the ```sc.sh``` script:

```
bash sc.sh <stats file> <path to binary>
```

So, to run SpecCheck on the precompiled POC for Spectre variant 1:

```
bash sc.sh v1.txt pocs/precompiled/spectre_v1_x86
```

To run standard gem5 without SpecCheck, use ```run.sh```:

```
bash run.sh <stats file> <path to binary>
```

## gem5 Configuration

Each experiment is configured to run using an x86 O3CPU in gem5's systemcall emulation mode. Each experiment uses the configuration available in ```configs/examples/se.py```, with 8GB of memory. More details about each experiments configuration can be found in ```sc.sh```.

## Statistics

The stats file given to the runner script will be located in ```m5out/``` and contains standard gem5 statistics with additional SpecCheck specific commit statistics (prefixed with ```speccheck```). SpecCheck saves all program counters flagged as potentially malicious during the experiments duration to ```m5out/<specified file>.scout```.
