#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>

#include "adbg.h"


// Detect debuggers via SIGTRAP handling
static int _debugger_present;


// Check if a string matches the name of a known debugging tool
static int _is_tool_name(const char *s)
{
	return (
		strstr(s, "gdb")   || strstr(s, "r2")     || strstr(s, "radare2") ||
		strstr(s, "ltrace")|| strstr(s, "strace") || strstr(s, "valgrind")
	);
}

// Detect LD_PRELOAD techniques
int adbg_check_ldpreload(void)
{
	// Check if LD_PRELOAD is set
	if (getenv("LD_PRELOAD")) {
		#ifdef DEBUG
		fputs("adbg_check_ldpreload: LD_PRELOAD is set\n", stderr);
		#endif

		return 1;
	}

	// Check for a custom getenv implementation by setting LD_PRELOAD and
	// checking whether it actually changed changed or not
	putenv("LD_PRELOAD=foo");

	if (strcmp(getenv("LD_PRELOAD"), "foo")) {
		unsetenv("LD_PRELOAD");

		#ifdef DEBUG
		fputs("adbg_check_ldpreload: custom getenv detected\n", stderr);
		#endif

		return 1;
	}

	unsetenv("LD_PRELOAD");
	return 0;
}

// Detect GDB fingerprints
int adbg_check_gdb(void)
{
	FILE *fp;
	char *s, path[1024];

	// Check for GDB path in _
	if (getenv("_")) {
		strncpy(path, getenv("_"), sizeof(path) - 1);

		s = strrchr(path, '/');
		s = s ? s + 1 : path;

		if (! strcmp(s, "gdb")) {
			#ifdef DEBUG
			fputs("adbg_check_gdb: environment variable _ contains 'gdb'\n", stderr);
			#endif

			return 1;
		}
	}

	// GDB sets LINES and COLUMNS
	if (getenv("LINES") || getenv("COLUMNS")) {
		#ifdef DEBUG
		fputs("adbg_check_gdb: GDB detected via LINES and/or COLUMNS\n", stderr);
		#endif

		return 1;
	}

	// GDB leaks 2 file descriptors when it opens a program to be debugged.
	// Both file descriptors are pointing to the file being debugged.
	if ((fp = fopen("/", "r"))) {
		if (fileno(fp) > 3) {
			#ifdef DEBUG
			fputs("adbg_check_gdb: GDB detected via file descriptor count\n", stderr);
			#endif

			fclose(fp);
			return 1;
		}

		fclose(fp);
	}

	return 0;
}

// Detect debugging tools via procfs
int adbg_check_parent(void)
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
				#ifdef DEBUG
				fputs(
					"adbg_check_parent: "
					"parent process is a debugging tool\n", stderr
				);
				#endif

				fclose(fp);
				return 1;
			}

		}

		fclose(fp);
	}

	// Check parent name in /proc/${PID}/cmdline
	snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", getppid());

	if (! (fp = fopen(buffer, "r"))) {
		#ifdef DEBUG
		perror("fopen");
		fprintf(stderr, "adbg_check_parent: failed to open '%s'; skipping other checks", buffer);
		#endif

		return 0;
	}

	if (fgets(buffer, sizeof(buffer), fp)) {
		s = strrchr(buffer, '/');
		s = s ? s + 1 : buffer;

		if (_is_tool_name(s)) {
			#ifdef DEBUG
			fputs("adbg_check_parent: parent process is a debugging tool\n", stderr);
			#endif

			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
}

// Detect SIGTRAP handling
static void _sigtrap_handler(int sig)
{
	if (sig == SIGTRAP)
		_debugger_present = 0;
}

int adbg_check_sigtrap(void)
{
	// Knowing that some debuggers handle SIGTRAP, if it's raised, _sigtrap_handler() should be
	// triggered
	_debugger_present = 1;
	signal(SIGTRAP, _sigtrap_handler);

	if (! raise(SIGTRAP) && _debugger_present) {
		#ifdef DEBUG
		fputs("adbg_check_sigtrap: SIGTRAP is being handled\n", stderr);
		#endif

		signal(SIGTRAP, SIG_DFL);
		return 1;
	}

	signal(SIGTRAP, SIG_DFL);
	return 0;
}

// Check if the current process has a tracer
int adbg_check_ptrace(void)
{
	// If this process cannot be traced, it already has a tracer
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
		#ifdef DEBUG
		fputs("adbg_check_ptrace: process has a tracer\n", stderr);
		#endif

		return 1;
	}

	// If the first call returned 0, the second should return -1 unless libc
	// was messed with (such as with LD_PRELOAD)
	if (! ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		#ifdef DEBUG
		fputs("adbg_check_ptrace: custom ptrace detected\n", stderr);
		#endif

		return 1;
	}

	return 0;
}

// Wrapper for all functions above
int adbg_check_all(void)
{
	return (
		adbg_check_ldpreload() ||
		adbg_check_gdb()       ||
		adbg_check_parent()    ||
		adbg_check_sigtrap()   ||
		adbg_check_ptrace()
	);
}
