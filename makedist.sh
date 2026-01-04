#!/bin/sh
#

DEBUG=

if test "x$1" = "x-d"; then
DEBUG=--enable-debug
fi

make distclean

# Reconfigure (with force) to get the latest revision from git
autoreconf -f

if ! ./configure ; then
	exit 1
fi

if ! make dist; then
	exit 1
fi
