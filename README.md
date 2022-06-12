adbg
====
Linux anti-debugging techniques.


Techniques
----------
- `adbg_env()`: Environment-related signs of debugging
- `adbg_gdb()`: Try to detect if GDB is handling the current process
- `adbg_proc()`: Detect various debugging tools via information under /proc/${PID}
- `adbg_ptrace()`: Detect if the current process has a tracer


Testing
-------
The test routine simply returns from `adbg_all()`, which wraps all functions. To enable debugging messages of failed tests, pass `-DDEBUG` to the compiler.

- Build and run the test binary:
`make && ./adbg-test`
