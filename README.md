adbg
====
Linux anti-debugging techniques.


Techniques
----------
- `adbg_check_ldpreload`: detect LD_PRELOAD techniques
- `adbg_check_gdb`: detect GDB fingerprints
- `adbg_check_parent`: detect debugging tools via procfs
- `adbg_check_sigtrap`: detect SIGTRAP handling
- `adbg_check_ptrace`: check if the current process has a tracer


Testing
-------
The test routine simply returns from `adbg_check_all()`, which wraps all functions. To enable debugging messages of failed tests, pass `-DDEBUG` to the compiler.

- Build the test binary `adbg-test` with `make` and run it using different debugging tools such as `strace`, `gdb`, `radare2`, etc. If the process returns 1, debugging behaviour was detected.
