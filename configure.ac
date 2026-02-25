dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])
dnl Get version number from git
m4_define([git_revision], m4_esyscmd_s([./autover.sh]))
AC_INIT([SnapRAID Daemon], [git_revision], [], [snapraid-daemon], [https://www.snapraid.it])
AM_INIT_AUTOMAKE([foreign no-dependencies subdir-objects])
AC_CONFIG_SRCDIR([daemon/daemon.c])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs.
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_CHECK_PROG([ADVD2],[advd2],[advd2],[])
AM_CONDITIONAL(HAVE_ADVD2, [test x"$ADVD2" != x])
AC_CHECK_PROG([ZIP],[zip],[zip],[])
AM_CONDITIONAL(HAVE_ZIP, [test x"$ZIP" != x])

dnl Options to improve stacktrace
AC_CHECK_CC_OPT([-fno-omit-frame-pointer], CFLAGS="$CFLAGS -fno-omit-frame-pointer", [])
AC_CHECK_CC_OPT([-fno-optimize-sibling-calls], CFLAGS="$CFLAGS -fno-optimize-sibling-calls", [])
AC_CHECK_CC_OPT([-rdynamic], CFLAGS="$CFLAGS -rdynamic", [])
# This the new default for gcc 10
AC_CHECK_CC_OPT([-fno-common], CFLAGS="$CFLAGS -fno-common", [])

dnl Hardening Flags
# -D_FORTIFY_SOURCE=2: 
# Adds checks for buffer overflows in common standard library functions. 
# Level 2 provides the most comprehensive checks available in modern glibc/gcc.
AC_CHECK_CC_OPT([-D_FORTIFY_SOURCE=2], CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2", [])

# -fstack-protector-strong: 
# Inserts a canary value before the stack return address. 
# "Strong" balances security and performance by protecting functions with 
# local arrays or address-taking of local variables.
AC_CHECK_CC_OPT([-fstack-protector-strong], CFLAGS="$CFLAGS -fstack-protector-strong", [])

# -fPIE / -pie: 
# Position Independent Executable. 
# Required for Address Space Layout Randomization (ASLR) to effectively 
# randomize the binary's location in memory.
AC_CHECK_CC_OPT([-fPIE], CFLAGS="$CFLAGS -fPIE", [])
AC_CHECK_CC_OPT([-pie], LDFLAGS="$LDFLAGS -pie", [])

# -Wl,-z,relro: 
# Read-Only Relocations. 
# Makes the Global Offset Table (GOT) read-only after the linker finishes.
AC_CHECK_CC_OPT([-z,relro], LDFLAGS="$LDFLAGS -z relro", [])

# -Wl,-z,now: 
# Immediate Binding (Full RELRO). 
# Works with 'relro' to resolve all symbols at startup, preventing 
# attackers from overwriting PLT/GOT entries later.
AC_CHECK_CC_OPT([-z,now], LDFLAGS="$LDFLAGS -z now", [])

# -Wl,-z,noexecstack: 
# Marks the stack as non-executable. 
# Prevents code execution even if an attacker successfully injects 
# shellcode onto the stack.
AC_CHECK_CC_OPT([-z,noexecstack], LDFLAGS="$LDFLAGS -z noexecstack", [])

# -fstack-clash-protection: 
# Prevents "stack clash" attacks by ensuring the stack 
# cannot grow into other memory regions without hitting a guard page.
AC_CHECK_CC_OPT([-fstack-clash-protection], CFLAGS="$CFLAGS -fstack-clash-protection", [])

# -fcf-protection: 
# Enables Intel CET (Control-flow Enforcement Technology). 
# Hardware-assisted protection against ROP (Return Oriented Programming) 
# and COP/JOP (Call/Jump Oriented Programming) on x86_64.
AC_CHECK_CC_OPT([-fcf-protection], CFLAGS="$CFLAGS -fcf-protection", [])

dnl Checks for system.
AC_SYS_LARGEFILE

dnl Checks for header files.
AC_HEADER_ASSERT
AC_HEADER_DIRENT
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h stdlib.h string.h limits.h time.h sys/time.h strings.h])
AC_CHECK_HEADERS([unistd.h getopt.h fnmatch.h io.h inttypes.h byteswap.h])
AC_CHECK_HEADERS([pthread.h math.h syslog.h grp.h pwd.h])
AC_CHECK_HEADERS([sys/sysinfo.h sys/utsname.h])

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
AC_SEARCH_LIBS([exp], [m])

dnl Checks for architecture
AC_C_BIGENDIAN

dnl Checks for libraries
PKG_CHECK_MODULES([ZLIB], [zlib >= 1.2.11], [
    AC_DEFINE([HAVE_ZLIB], [1], [Define if you have zlib])
    AC_SUBST([ZLIB_CFLAGS])
    AC_SUBST([ZLIB_LIBS])
], [
    AC_MSG_WARN([zlib not found. Gzip support will be disabled.])
])

PKG_CHECK_MODULES([ZSTD], [libzstd >= 1.4.0], [
    AC_DEFINE([HAVE_ZSTD], [1], [Define if you have libzstd])
    AC_SUBST([ZSTD_CFLAGS])
    AC_SUBST([ZSTD_LIBS])
], [
    AC_MSG_WARN([libzstd not found. Zstd support will be disabled.])
])

dnl Checks for compiler
AC_CHECK_CC_OPT([-Wall], CFLAGS="$CFLAGS -Wall", [])
AC_CHECK_CC_OPT([-Wextra], CFLAGS="$CFLAGS -Wextra", [])
AC_CHECK_CC_OPT([-Wuninitialized], CFLAGS="$CFLAGS -Wuninitialized", [])
AC_CHECK_CC_OPT([-Wshadow], CFLAGS="$CFLAGS -Wshadow", [])

dnl Options to improve stacktrace
AC_CHECK_CC_OPT([-fno-omit-frame-pointer], CFLAGS="$CFLAGS -fno-omit-frame-pointer", [])
AC_CHECK_CC_OPT([-fno-inline-functions-called-once], CFLAGS="$CFLAGS -fno-inline-functions-called-once", [])
AC_CHECK_CC_OPT([-fno-inline-small-functions], CFLAGS="$CFLAGS -fno-inline-small-functions", [])
AC_CHECK_CC_OPT([-fno-optimize-sibling-calls], CFLAGS="$CFLAGS -fno-optimize-sibling-calls", [])
AC_CHECK_CC_OPT([-rdynamic], CFLAGS="$CFLAGS -rdynamic", [])
# This the new default for gcc 10
AC_CHECK_CC_OPT([-fno-common], CFLAGS="$CFLAGS -fno-common", [])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],[enable debugging])],
	[
	CFLAGS="-O0 -g -pthread -Wall -Wextra -fno-omit-frame-pointer -rdynamic"
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

AC_ARG_WITH([init-type],
    [AS_HELP_STRING([--with-init-type=TYPE], [Init system type: systemd, bsd, or none (default: auto)])],
    [init_type=$withval],
    [init_type=auto])

AC_MSG_CHECKING([checking init system])
if test "x$init_type" = "xauto"; then
    # Check systemd first (more specific)
    if $PKG_CONFIG --exists systemd; then
        init_type=systemd
    # Then check for BSD directory existence
    elif test -d /etc/rc.d; then
        init_type=bsd
    else
        init_type=none
    fi
fi
AC_MSG_RESULT([$init_type])

if test "x$init_type" = "xsystemd"; then
  # Set a default for SERVICEDIR based on prefix
  if test "x$prefix" = "x/usr"; then
    # Standard system install: Use pkg-config to find the "real" path
    PKG_CHECK_EXISTS([systemd], 
      [default_unitdir=`$PKG_CONFIG --variable=systemdsystemunitdir systemd`],
      [default_unitdir='${libdir}/systemd/system'])
  else
      # Custom/Local install: Keep it inside the prefix sandbox
      default_unitdir='${libdir}/systemd/system'
  fi
  AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [directory for systemd service files (default: PREFIX/lib/systemd/system)])],
    [SERVICEDIR="$with_systemdsystemunitdir"],
    [SERVICEDIR="$default_unitdir"]
  )
  AC_SUBST([SERVICEDIR])
fi

if test "x$init_type" = "xbsd"; then
  # Check OS type via $host_os (provided by AC_CANONICAL_HOST)
  case "$host_os" in
    *linux*)
      # Slackware case: Prefix /usr means /etc/rc.d
      if test "x$prefix" = "x/usr"; then
          default_rcdir='/etc/rc.d'
      else
          default_rcdir='${sysconfdir}/rc.d'
      fi
      ;;
    *)
      # True BSD case: Usually ${prefix}/etc/rc.d
      default_rcdir='${sysconfdir}/rc.d'
      ;;
  esac
  AC_ARG_WITH([rcdir],
    [AS_HELP_STRING([--with-rcdir=DIR], [directory for BSD init scripts (default: PREFIX/etc/rc.d)])],
    [RCDIR="$with_rcdir"],
    [RCDIR="$default_rcdir"]
  )
  AC_SUBST([RCDIR])
fi

if test "x$init_type" = "xsystemd"; then
    AC_MSG_CHECKING([for systemdsystemunitdir])
    
    # Resolve the path safely in a subshell without changing prefix/execprefix in the parent shell
    actual_unitdir=$(
        # Resolve NONE to defaults locally
        test "x$prefix" = xNONE && prefix="$ac_default_prefix"
        test "x$exec_prefix" = xNONE && exec_prefix="$prefix"

        # Loop multiple times to ensure we resolve all variables: ${libdir} -> ${exec_prefix} -> /usr/local
        res="$SERVICEDIR"
        eval res=\"$res\"
        eval res=\"$res\"
        eval res=\"$res\"
        echo "$res"
    )
    AC_MSG_RESULT([$actual_unitdir])
fi

if test "x$init_type" = "xbsd"; then
    AC_MSG_CHECKING([for rcdir])
    
    # Resolve the path safely in a subshell without changing prefix/execprefix in the parent shell
    actual_rcdir=$(
        # Resolve NONE to defaults locally
        test "x$prefix" = xNONE && prefix="$ac_default_prefix"
        test "x$exec_prefix" = xNONE && exec_prefix="$prefix"

        # Loop multiple times to ensure we resolve all variables: ${sysconfdir} -> ${prefix} -> /usr/local
        res="$RCDIR"
        eval res=\"$res\"
        eval res=\"$res\"
        eval res=\"$res\"
        echo "$res"
    )
    AC_MSG_RESULT([$actual_rcdir])
fi

# Set Automake conditionals for the Makefile
AM_CONDITIONAL([INSTALL_SYSTEMD], [test "x$init_type" = "xsystemd"])
AM_CONDITIONAL([INSTALL_BSD_INIT], [test "x$init_type" = "xbsd"])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([pkg/snapraid-daemon.info pkg/control pkg/snapraid-daemon.spec])
AC_CONFIG_FILES([makeslackware.sh], [chmod a+x makeslackware.sh])
AC_CONFIG_FILES([makeslackdist.sh], [chmod a+x makeslackdist.sh])
AC_CONFIG_FILES([pkg/snapraid-daemon.SlackBuild], [chmod a+x pkg/snapraid-daemon.SlackBuild])
AC_CONFIG_FILES([makedeb.sh], [chmod a+x makedeb.sh])
AC_CONFIG_FILES([makerpm.sh], [chmod a+x makerpm.sh])

# Override datadir to be snapraidd and not snapraid-daemon
datadir='${prefix}/share/snapraidd'
AC_SUBST([datadir]) 

AC_OUTPUT
