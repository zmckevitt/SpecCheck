# SpecCheck

To run a program with SpecCheck, run it as follows:

```build/X86/gem5.opt --debug-flags=SpecCheck configs/o3-ltage.py <path-to-binary>```

To specify a stats file:

```build/X86/gem5.opt --debug-flags=SpecCheck --stats-file=<stats-file.txt> configs/o3-ltage.py <path-to-binary>```
