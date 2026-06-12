dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])
dnl Get version number from git
m4_define([git_revision], m4_esyscmd_s([./autover.sh]))
AC_INIT([SnapRAID Daemon], [git_revision], [], [snapraid-daemon], [https://www.snapraid.it])
AC_CANONICAL_HOST
AC_CANONICAL_BUILD
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign no-dependencies subdir-objects])
AC_CONFIG_SRCDIR([daemon/portable.h])
AC_CONFIG_HEADERS([config.h])

dnl Enables as many system-specific extensions as reasonably possible
AC_USE_SYSTEM_EXTENSIONS

dnl Macro directory
AC_CONFIG_MACRO_DIRS([m4])

dnl Checks for programs.
AC_PROG_CC
AC_CHECK_PROG([ADVD2],[advd2],[advd2],[])
AM_CONDITIONAL(HAVE_ADVD2, [test x"$ADVD2" != x])
AC_CHECK_PROG([ZIP], [zip], [zip])

if test "x$ZIP" = "x"; then
    AC_MSG_ERROR([The zip utility is required during the build process. Please ensure it is installed on your system.])
fi

# Compile a quick test program using a syntax unique to C99 and newer
AC_MSG_CHECKING([if compiler supports C99 or newer features])
AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[]], [[
        int x = 0;
        x++;
        int y = x;
        int array[y];
    ]])
], [
    AC_MSG_RESULT([yes])
], [
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([A C99-compliant compiler or newer is required to build this package.])
])

# Check if we are targeting Windows
is_windows=no
AS_CASE([$host_os], [mingw*|msys*|cygwin*], [is_windows=yes])
AM_CONDITIONAL([HOST_WINDOWS], [test "x$is_windows" = "xyes"])

# Check for Windows-specific tools only if on Windows
if test "x$is_windows" = "xyes"; then
    AC_CHECK_TOOL([WINDMC], [windmc])
    AC_CHECK_TOOL([WINDRES], [windres])
fi

dnl Options to improve stacktrace
AX_CHECK_COMPILE_FLAG([-fno-omit-frame-pointer], CFLAGS="$CFLAGS -fno-omit-frame-pointer", [])
AX_CHECK_COMPILE_FLAG([-fno-optimize-sibling-calls], CFLAGS="$CFLAGS -fno-optimize-sibling-calls", [])
AX_CHECK_COMPILE_FLAG([-rdynamic], CFLAGS="$CFLAGS -rdynamic", [])
# This the new default for gcc 10
AX_CHECK_COMPILE_FLAG([-fno-common], CFLAGS="$CFLAGS -fno-common", [])

dnl Hardening Flags
if test "x$is_windows" = "xno"; then
# -D_FORTIFY_SOURCE=2: 
# Adds checks for buffer overflows in common standard library functions. 
# Level 2 provides the most comprehensive checks available in modern glibc/gcc.
AX_CHECK_COMPILE_FLAG([-D_FORTIFY_SOURCE=2], CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2", [])

# -fstack-protector-strong: 
# Inserts a canary value before the stack return address. 
# "Strong" balances security and performance by protecting functions with 
# local arrays or address-taking of local variables.
AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], CFLAGS="$CFLAGS -fstack-protector-strong", [])

# -fPIE / -pie: 
# Position Independent Executable. 
# Required for Address Space Layout Randomization (ASLR) to effectively 
# randomize the binary's location in memory.
AX_CHECK_COMPILE_FLAG([-fPIE], CFLAGS="$CFLAGS -fPIE", [])
AX_CHECK_COMPILE_FLAG([-pie], LDFLAGS="$LDFLAGS -pie", [])

# -Wl,-z,relro: 
# Read-Only Relocations. 
# Makes the Global Offset Table (GOT) read-only after the linker finishes.
AX_CHECK_COMPILE_FLAG([-z,relro], LDFLAGS="$LDFLAGS -z relro", [])

# -Wl,-z,now: 
# Immediate Binding (Full RELRO). 
# Works with 'relro' to resolve all symbols at startup, preventing 
# attackers from overwriting PLT/GOT entries later.
AX_CHECK_COMPILE_FLAG([-z,now], LDFLAGS="$LDFLAGS -z now", [])

# -Wl,-z,noexecstack: 
# Marks the stack as non-executable. 
# Prevents code execution even if an attacker successfully injects 
# shellcode onto the stack.
AX_CHECK_COMPILE_FLAG([-z,noexecstack], LDFLAGS="$LDFLAGS -z noexecstack", [])

# -fstack-clash-protection: 
# Prevents "stack clash" attacks by ensuring the stack 
# cannot grow into other memory regions without hitting a guard page.
AX_CHECK_COMPILE_FLAG([-fstack-clash-protection], CFLAGS="$CFLAGS -fstack-clash-protection", [])

# -fcf-protection: 
# Enables Intel CET (Control-flow Enforcement Technology). 
# Hardware-assisted protection against ROP (Return Oriented Programming) 
# and COP/JOP (Call/Jump Oriented Programming) on x86_64.
AX_CHECK_COMPILE_FLAG([-fcf-protection], CFLAGS="$CFLAGS -fcf-protection", [])
fi

dnl Checks for system.
AC_SYS_LARGEFILE

dnl Checks for architecture
AC_C_BIGENDIAN

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
AC_CHECK_FUNCS([fexecve pipe2])
AC_SEARCH_LIBS([exp], [m])
AC_CHECK_FUNCS([eaccess faccessat])
AC_SEARCH_LIBS([gethostbyname], [ws2_32])

dnl Checks for libraries
have_pthreads=no
AS_IF([test "x$is_windows" = "xyes"], [
	AC_MSG_NOTICE([Windows native threads support enabled])
], [
    AC_CHECK_HEADERS([pthread.h])
    AX_PTHREAD([
        thread_model="pthreads"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_DEFINE([HAVE_PTHREAD], [1], [Define to 1 if POSIX threads are available])
        AC_MSG_NOTICE([POSIX threads support enabled])
    ], [
        AC_MSG_WARN([Single-threaded version])
    ])
])
AM_CONDITIONAL([HAVE_PTHREAD], [test "x$have_pthreads" = "xyes"])

AC_CHECK_HEADER([zlib.h], [
    AC_CHECK_LIB([z], [gzopen], [
        AC_DEFINE([HAVE_ZLIB], [1], [Define if you have zlib])
        ZLIB_LIBS="-lz"
        AC_SUBST([ZLIB_LIBS])
    ], [
        AC_MSG_WARN([zlib library not found. Gzip support disabled.])
    ])
], [
    AC_MSG_WARN([zlib headers not found. Gzip support disabled.])
])

dnl Checks for libzstd
AC_CHECK_HEADER([zstd.h], [
    AC_CHECK_LIB([zstd], [ZSTD_compress], [
        AC_DEFINE([HAVE_ZSTD], [1], [Define if you have libzstd])
        ZSTD_LIBS="-lzstd"
        AC_SUBST([ZSTD_LIBS])
    ], [
        AC_MSG_WARN([libzstd library not found. Zstd support disabled.])
    ])
], [
    AC_MSG_WARN([libzstd headers not found. Zstd support disabled.])
])

dnl Checks for compiler
AX_CHECK_COMPILE_FLAG([-Wall], CFLAGS="$CFLAGS -Wall", [])
AX_CHECK_COMPILE_FLAG([-Wextra], CFLAGS="$CFLAGS -Wextra", [])
AX_CHECK_COMPILE_FLAG([-Wuninitialized], CFLAGS="$CFLAGS -Wuninitialized", [])
AX_CHECK_COMPILE_FLAG([-Wshadow], CFLAGS="$CFLAGS -Wshadow", [])

dnl Options to improve stacktrace
AX_CHECK_COMPILE_FLAG([-fno-omit-frame-pointer], CFLAGS="$CFLAGS -fno-omit-frame-pointer", [])
AX_CHECK_COMPILE_FLAG([-fno-inline-functions-called-once], CFLAGS="$CFLAGS -fno-inline-functions-called-once", [])
AX_CHECK_COMPILE_FLAG([-fno-inline-small-functions], CFLAGS="$CFLAGS -fno-inline-small-functions", [])
AX_CHECK_COMPILE_FLAG([-fno-optimize-sibling-calls], CFLAGS="$CFLAGS -fno-optimize-sibling-calls", [])
AX_CHECK_COMPILE_FLAG([-rdynamic], CFLAGS="$CFLAGS -rdynamic", [])
# This the new default for gcc 10
AX_CHECK_COMPILE_FLAG([-fno-common], CFLAGS="$CFLAGS -fno-common", [])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],[enable debugging])],
	[
	CFLAGS="-O0 -g -pthread -Wall -Wextra -fno-omit-frame-pointer -rdynamic"
	LDFLAGS="-g"
	],
	[])

AC_ARG_ENABLE([warning-as-error],
	[AS_HELP_STRING([--enable-warning-as-error],[stop build on warnings])],
	[
	AX_CHECK_COMPILE_FLAG([-Werror], CFLAGS="$CFLAGS -Werror", [])
	dnl This avoid the Darwin error: clang: error: argument unused during compilation: '-pthread'
	dnl See: https://llvm.org/bugs/show_bug.cgi?id=7798
	AX_CHECK_COMPILE_FLAG([-Wno-error=unused-command-line-argument], CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument", [])
	],
	[])

AC_ARG_ENABLE([warning],
	[AS_HELP_STRING([--enable-warning],[enable extra warning])],
	[
	AX_CHECK_COMPILE_FLAG([-Wpointer-arith], CFLAGS="$CFLAGS -Wpointer-arith", [])
	AX_CHECK_COMPILE_FLAG([-Wcast-qual], CFLAGS="$CFLAGS -Wcast-qual", [])
	AX_CHECK_COMPILE_FLAG([-Wunused], CFLAGS="$CFLAGS -Wunused", [])
	AX_CHECK_COMPILE_FLAG([-Wunreachable-code], CFLAGS="$CFLAGS -Wunreachable-code", [])
	AX_CHECK_COMPILE_FLAG([-Wpadded], CFLAGS="$CFLAGS -Wpadded", [])
	AX_CHECK_COMPILE_FLAG([-Weverything], CFLAGS="$CFLAGS -Weverything", [])
	],
	[])

AC_ARG_WITH([init-type],
    [AS_HELP_STRING([--with-init-type=TYPE], [Init system type: systemd, bsd, or none (default: auto)])],
    [init_type=$withval],
    [init_type=auto])

AC_MSG_CHECKING([for init system])
if test "x$init_type" = "xauto"; then
  # Check for standard systemd directories
  if test -d /usr/lib/systemd/system || test -d /lib/systemd/system; then
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
    # Standard system install
    if test -d /usr/lib/systemd/system; then
        default_unitdir=/usr/lib/systemd/system
    else
        default_unitdir=/lib/systemd/system
    fi
  else
      # Custom/Local install: Keep it inside the prefix sandbox
      default_unitdir='${libdir}/systemd/system'
  fi
  AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [directory for systemd service files (default: from pkg-config, or /usr/lib/systemd/system for system installs, or \${libdir}/systemd/system for custom prefix installs)])],
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

# WITH_TOOL(NAME, BINARY, DESCRIPTION)
# Adds --with-NAME=PATH option. Defines NAME_PATH if given.
AC_DEFUN([WITH_TOOL], [
    AC_ARG_WITH([$1],
        [AS_HELP_STRING([--with-$1=PATH],
            [absolute path to the $2 executable ($3)])],
        [
            AS_CASE([$withval],
                [/*], [],
                [AC_MSG_ERROR([--with-$1 requires an absolute path (got '$withval')])])
            AS_IF([test ! -x "$withval"],
                [AC_MSG_WARN([$2 not found or not executable at '$withval'])])
            AC_DEFINE_UNQUOTED(m4_toupper([$1_PATH]), ["$withval"], 
                [Absolute path to $2, set at configure time.])
            AC_MSG_NOTICE([$2: $withval])
        ],
        [
            AC_MSG_NOTICE([$2: use runtime discovery])
        ])
])

WITH_TOOL([snapraid], [snapraid],  [SnapRAID CLI engine])
WITH_TOOL([curl], [curl], [curl CLI tool])
WITH_TOOL([docker], [docker], [docker CLI])

# Set Automake conditionals for the Makefile
AM_CONDITIONAL([INSTALL_SYSTEMD], [test "x$init_type" = "xsystemd"])
AM_CONDITIONAL([INSTALL_BSD_INIT], [test "x$init_type" = "xbsd"])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([pkg/snapraid-daemon.info pkg/control pkg/snapraid-daemon.spec pkg/.PKGINFO pkg/PKGBUILD pkg/.SRCINFO pkg/snapraid-daemon.nsis])
AC_CONFIG_FILES([makeslackware.sh], [chmod a+x makeslackware.sh])
AC_CONFIG_FILES([makeslackdist.sh], [chmod a+x makeslackdist.sh])
AC_CONFIG_FILES([pkg/snapraid-daemon.SlackBuild], [chmod a+x pkg/snapraid-daemon.SlackBuild])
AC_CONFIG_FILES([makedeb.sh], [chmod a+x makedeb.sh])
AC_CONFIG_FILES([makerpm.sh], [chmod a+x makerpm.sh])
AC_CONFIG_FILES([makearch.sh], [chmod a+x makearch.sh])
AC_CONFIG_FILES([makearchdist.sh], [chmod a+x makearchdist.sh])
AC_CONFIG_FILES([makensis.sh], [chmod a+x makensis.sh])

# Override datadir to be snapraidd and not snapraid-daemon
datadir='${prefix}/share/snapraidd'
AC_SUBST([datadir]) 

AC_OUTPUT
