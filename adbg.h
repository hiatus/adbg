#ifndef ADBG_H
#define ADBG_H

#include <stdbool.h>

// Wrapper for all functions
bool adbg_all(void);
// Try to detect environment-related debugging signs
bool adbg_env(void);
// Try to detect GDB
bool adbg_gdb(void);
// Try to detect debugging tools via information under /proc/${PID}
bool adbg_proc(void);
// Try to detect if the current process has a tracer
bool adbg_ptrace(void);
#endif
