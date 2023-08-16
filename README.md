# SpecCheck

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

The ```pocs/``` directory contains proof of concept binaies for Spectre variant 1 (Pattern History Table), variant 2 (Branch Target Buffer), variant 3 (Retun Stack Buffer), and variant 4 (Store to Load Forwarding). Each proof of concept was compiled on x86 Ubuntu 20.04 and statically linked. More information about each proof of concept can be found in ```POCs.md```.

While in the gem5 directory, save the current working directory to an environment variable to be used in runner scripts:

```
export GEM5_PATH=$(pwd)
```

To run gem5 with SpecCheck enabled, use the ```sc.sh``` script:

```
bash sc.sh <stats file> <path to binary>
```

So, to run SpecCheck on Spectre variant 1:

```
bash sc.sh v1.txt pocs/spectre_v1
```

The stats file specified will be located in ```m5out/``` under the name supplied to the runner file. ```m5out/SpecCheck.out``` contains all program counters flagged as potentially malicious during the experiments duration.

To run standard gem5 without SpecCheck, use ```run.sh```:

```
bash run.sh <stats file> <path to binary>
```

## gem5 Configuration

Each experiment is configured to run using an x86 O3CPU in gem5's systemcall emulation mode. Each experiment uses the configuration available in ```configs/examples/se.py```, with 8GB of memory. More details about each experiments configuration can be found in ```sc.sh```.
