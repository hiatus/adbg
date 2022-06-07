#include "adbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ptrace.h>

// Check if string matches any of various debugging tools names
static inline bool _is_tool_name(const char *s)
{
	return (
		strstr(s, "gdb")   || strstr(s, "r2")     || strstr(s, "radare2") ||
		strstr(s, "ltrace")|| strstr(s, "strace") || strstr(s, "valgrind")
	);
}

// Try to detect environment-related debugging signs
bool adbg_env(void)
{
	char *s, path[64];

	// Check if LD_PRELOAD is set
	if (getenv("LD_PRELOAD")) {
#ifdef DEBUG
		fputs("adbg_env: LD_PRELOAD is set\n", stderr);
#endif
		return true;
	}

	// Check for a custom getenv implementation
	putenv("LD_PRELOAD=foo");

	if (strcmp(getenv("LD_PRELOAD"), "foo")) {
		unsetenv("LD_PRELOAD");
#ifdef DEBUG
		fputs("adbg_env: custom getenv implementation\n", stderr);
#endif
		return true;
	}

	unsetenv("LD_PRELOAD");
	
	// Check for GDB path
	if (getenv("_")) {
		strncpy(path, getenv("_"), sizeof(path) - 1);

		s = strrchr(path, '/');
		s = s ? s + 1 : path;

		if (! strcmp(s, "gdb")) {
#ifdef DEBUG
			fputs("adbg_env: getenv('_') contains GDB PATH\n", stderr);
#endif
			return true;
		}
	}

	return false;
}

// Try to detect GDB
static bool _gdb_present;

static void _gdb_sigtrap_handler(int sig)
{
	_gdb_present = false;
}

bool adbg_gdb(void)
{
	FILE *fp;

	// GDB sets LINES and COLUMNS
	if (getenv("LINES") || getenv("COLUMNS")) {
#ifdef DEBUG
		fputs("adbg_gdb: environment variables LINES and/or COLUMNS found\n", stderr);
#endif
		return true;
	}

	// GDB leaks 2 file descriptors when it opens a program to be debugged.
	// Both file descriptors are pointing to the file being debugged.
	if ((fp = fopen("/", "r"))) {
		if (fileno(fp) > 3) {
#ifdef DEBUG
			fputs("adbg_gdb: new file descriptor number greater than 3", stderr);
#endif
			fclose(fp);
			return true;
		}

		fclose(fp);
	}

	// Knowing that GDB handles SIGTRAP, if raised, _gdb_sigtrap_handler()
	// would not be triggered
	_gdb_present = true;
	signal(SIGTRAP, _gdb_sigtrap_handler);

	if (! raise(SIGTRAP) && _gdb_present) {
		#ifdef DEBUG
			fputs("adbg_gdb: SIGTRAP possibly being handled by GDB\n", stderr);
		#endif

		return true;
	}

	signal(SIGTRAP, SIG_DFL);

	return false;
}

// Try to detect debugging tools via information under /proc/${PID}
bool adbg_proc(void)
{
	FILE *fp;

	char *s;
	char buffer[64];

	// Check parent name in /proc/${PID}/status
	snprintf(buffer, sizeof(buffer), "/proc/%i/status", getppid());

	if ((fp = fopen(buffer, "r"))) {
		if (fgets(buffer, sizeof(buffer), fp)) {
			s = strrchr(buffer, '/');
			s = s ? s + 1 : buffer;

			if (_is_tool_name(s)) {
				fclose(fp);
#ifdef DEBUG
				fputs("adbg_proc: /proc/PID/status contains known debugging tool name\n", stderr);
#endif
				return true;
			}

		}

		fclose(fp);
	}

	// Check parent name in /proc/${PID}/cmdline
	snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", getppid());

	if (! (fp = fopen(buffer, "r")))
		return false;

	if (fgets(buffer, sizeof(buffer), fp)) {
		s = strrchr(buffer, '/');
		s = s ? s + 1 : buffer;

		if (_is_tool_name(s)) {
			fclose(fp);
#ifdef DEBUG
			fputs("adbg_proc: /proc/PID/cmdline contains known debugging tool name\n", stderr);
#endif
			return true;
		}
	}

	fclose(fp);
	return false;
}

// Try to detect if the current process has a tracer
bool adbg_ptrace(void)
{
	// If this process cannot be traced, it already has a tracer
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
#ifdef DEBUG
		fputs("adbg_ptrace: process has a tracer\n", stderr);
#endif
		return true;
	}

	// If the first call returned 0, the second should return -1 unless libc
	// was messed with (such as with LD_PRELOAD)
	if (! ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
#ifdef DEBUG
		fputs("adbg_ptrace: possible ptrace implementation intercepting legitimate call\n", stderr);
#endif
		return true;
	}

	return false;
}

// Wrapper for all functions above
bool adbg_all(void)
{
	return (
		adbg_env() || adbg_gdb() || adbg_proc() || adbg_ptrace()
	);
}
