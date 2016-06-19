This is a codebase intended to be used with userland application exploits for Nintendo 3DS.

Essentially, the idea is to have this handle most of the ROP-chain + locating gadgets, with the exploit just using the macros it needs etc. This is not yet ready to be used in exploits however. Hence, this would be somewhat similar to this: https://github.com/yellows8/3ds_browserhax_common

Currently this is only usable with GCC with the "-x assembler-with-cpp" build option.

This requires [ropgadget_patternfinder](https://github.com/yellows8/ropgadget_patternfinder).

