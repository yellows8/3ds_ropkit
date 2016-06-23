This is a codebase intended to be used with userland title exploits in general for Nintendo 3DS.

The exploit would use the scripts here for locating the required ROP addrs. Then in the .s, it would include "ropkit_ropinclude.s", and if this is an regular-application "ropkit_boototherapp.s". Hence, this is somewhat similar to this: https://github.com/yellows8/3ds_browserhax_common

Currently this is only usable with GCC with the "-x assembler-with-cpp" build option.

This requires [ropgadget_patternfinder](https://github.com/yellows8/ropgadget_patternfinder).

