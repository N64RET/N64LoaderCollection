# Base Nintendo 64 Loader

This loader creates the Nintendo 64 memory map, adds hardware registers and loads the specified ROM accordingly to the IPL3 code.

Optionally:
- You can load a PIF ROM by specifying its path in the loader options.
- You can choose to find and load the boot segment only. (This will analyze the entrypoint code to locate .bss)