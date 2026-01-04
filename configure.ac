dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])
dnl Get version number from git
m4_define([git_revision], m4_esyscmd_s([./autover.sh]))
AC_INIT([snapraidd], [git_revision], [], [], [https://www.snapraid.it])
AM_INIT_AUTOMAKE([foreign no-dependencies subdir-objects])
AC_CONFIG_SRCDIR([daemon/daemon.c])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_CHECK_PROG([ADVD2],[advd2],[advd2],[])
AM_CONDITIONAL(HAVE_ADVD2, [test x"$ADVD2" != x])

dnl Options to improve stacktrace
AC_CHECK_CC_OPT([-fno-omit-frame-pointer], CFLAGS="$CFLAGS -fno-omit-frame-pointer", [])
AC_CHECK_CC_OPT([-fno-optimize-sibling-calls], CFLAGS="$CFLAGS -fno-optimize-sibling-calls", [])
AC_CHECK_CC_OPT([-rdynamic], CFLAGS="$CFLAGS -rdynamic", [])
# This the new default for gcc 10
AC_CHECK_CC_OPT([-fno-common], CFLAGS="$CFLAGS -fno-common", [])

dnl Checks for system.
AC_SYS_LARGEFILE

dnl Checks for header files.
AC_HEADER_ASSERT
AC_HEADER_DIRENT
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h stdlib.h string.h limits.h time.h sys/time.h strings.h])
AC_CHECK_HEADERS([unistd.h getopt.h fnmatch.h io.h inttypes.h byteswap.h])
AC_CHECK_HEADERS([pthread.h math.h syslog.h grp.h pwd.h])

# Check for the close_range(...,CLOSE_RANGE_CLOEXEC)
AC_CHECK_HEADERS([linux/close_range.h])
AC_CHECK_FUNCS([close_range])
AC_MSG_CHECKING([for CLOSE_RANGE_CLOEXEC])
AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
        #ifdef HAVE_LINUX_CLOSE_RANGE_H
        #include <linux/close_range.h>
        #endif
        #include <unistd.h>
    ]], [[
        unsigned int flags = CLOSE_RANGE_CLOEXEC;
    ]])
], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_CLOSE_RANGE_CLOEXEC], [1], [Define if CLOSE_RANGE_CLOEXEC is available])
], [
    AC_MSG_RESULT([no])
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_RESTRICT
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_TYPE_INT8_T
AC_STRUCT_DIRENT_D_INO
AC_STRUCT_DIRENT_D_TYPE

dnl Checks for library functions.
AC_CHECK_FUNCS([memset strchr strerror strrchr mkdir gettimeofday strtoul strlcpy])
AC_CHECK_FUNCS([getopt getopt_long snprintf vsnprintf sigaction])
AC_CHECK_CC_OPT([-pthread], CFLAGS="$CFLAGS -pthread", CFLAGS="$CFLAGS -D_REENTRANT")
AC_CHECK_FUNCS([pthread_create])
AC_CHECK_FUNCS([fexecve pipe2])

dnl Checks for architecture
AC_C_BIGENDIAN

dnl Checks for compiler
AC_CHECK_CC_OPT([-Wall], CFLAGS="$CFLAGS -Wall", [])
AC_CHECK_CC_OPT([-Wextra], CFLAGS="$CFLAGS -Wextra", [])
AC_CHECK_CC_OPT([-Wuninitialized], CFLAGS="$CFLAGS -Wuninitialized", [])
AC_CHECK_CC_OPT([-Wshadow], CFLAGS="$CFLAGS -Wshadow", [])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],[enable debugging])],
	[
	CFLAGS="-Og -g -pthread -Wall -Wextra"
	AC_CHECK_CC_OPT([-rdynamic], CFLAGS="$CFLAGS -rdynamic", [])
	],
	[])

AC_ARG_ENABLE([warning-as-error],
	[AS_HELP_STRING([--enable-warning-as-error],[stop build on warnings])],
	[
	AC_CHECK_CC_OPT([-Werror], CFLAGS="$CFLAGS -Werror", [])
	dnl This avoid the Darwin error: clang: error: argument unused during compilation: '-pthread'
	dnl See: https://llvm.org/bugs/show_bug.cgi?id=7798
	AC_CHECK_CC_OPT([-Wno-error=unused-command-line-argument], CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument", [])
	],
	[])

AC_ARG_ENABLE([warning],
	[AS_HELP_STRING([--enable-warning],[enable extra warning])],
	[
	AC_CHECK_CC_OPT([-Wpointer-arith], CFLAGS="$CFLAGS -Wpointer-arith", [])
	AC_CHECK_CC_OPT([-Wcast-qual], CFLAGS="$CFLAGS -Wcast-qual", [])
	AC_CHECK_CC_OPT([-Wunused], CFLAGS="$CFLAGS -Wunused", [])
	AC_CHECK_CC_OPT([-Wunreachable-code], CFLAGS="$CFLAGS -Wunreachable-code", [])
	AC_CHECK_CC_OPT([-Wpadded], CFLAGS="$CFLAGS -Wpadded", [])
	AC_CHECK_CC_OPT([-Weverything], CFLAGS="$CFLAGS -Weverything", [])
	],
	[])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
