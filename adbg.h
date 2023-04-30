#ifndef ADBG_H
#define ADBG_H

// Detect LD_PRELOAD techniques
int adbg_check_ldpreload(void);
// Detect GDB fingerprints
int adbg_check_gdb(void);
// Detect debugging tools via procfs
int adbg_check_parent(void);
// Detect SIGTRAP handling
int adbg_check_sigtrap(void);
// Check if the current process has a tracer
int adbg_check_ptrace(void);
// Wrapper for all functions above
int adbg_check_all(void);
#endif
