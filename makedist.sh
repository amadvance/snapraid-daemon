#!/bin/sh
#

DEBUG=

if test "x$1" = "x-d"; then
DEBUG=--enable-debug
fi

# Ask permission at the start
sudo echo We are root

make distclean

# Reconfigure (with force) to get the latest revision from git
autoreconf -f

if ! ./configure ; then
	exit 1
fi

if ! make dist; then
	exit 1
fi

sh makensis.sh
sh makeslackdist.sh
sudo sh makeslackware.sh
sudo sh makedeb.sh
sudo sh makerpm.sh
