#                                              -*- Autoconf -*-
#
# Copyright (c) 2008-2009 Members of the EGEE Collaboration.
# See http://www.eu-egee.org/partners for details on the copyright holders. 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Id: configure.ac 1299 2009-10-15 15:29:34Z vtschopp $
#

AC_INIT([argus-pepcli], [2.2.0], [argus-support@cern.ch])
AC_CONFIG_AUX_DIR([project])
AC_CONFIG_MACRO_DIR([project])

# OSX requires ./configure --disable-dependency-tracking to compile, others don't care
AM_INIT_AUTOMAKE([no-dependencies])
# disable static library
AM_DISABLE_STATIC

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC
AM_PROG_CC_C_O
# problem on SL5
#AC_PROG_MKDIR_P 
AC_PROG_INSTALL
AC_PROG_LN_S

# Check for doxygen
AC_CHECK_PROG(DOXYGEN,[doxygen],[doxygen],[$ac_aux_dir/missing --run doxygen])
AC_SUBST(DOXYGEN)

# GCC CFLAGS
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -Wall "
fi
# OSX CFLAGS
#case $host in
#*-*-darwin*)
#    CFLAGS="$CFLAGS -arch i386 -arch x86_64 -mmacosx-version-min=10.5 -iwithsysroot=/Developer/SDKs/MacOSX10.5.sdk"
#    AC_MSG_NOTICE([Mac OSX ($host_os) CFLAGS: $CFLAGS])
#    ;;
#esac

AC_MSG_NOTICE([libdir for $host: $libdir])

# Checks for PEP client API headers and library
#
# use environment variable PKG_CONFIG_PATH=$libdir/pkgconfig
#
AC_MSG_NOTICE([pkg-config libargus-pep >= 2])
PKG_CHECK_MODULES(LIBARGUS_PEP,
    [libargus-pep >= 2],
    [
        AC_MSG_NOTICE([LIBARGUS_PEP_CFLAGS=$LIBARGUS_PEP_CFLAGS])
        AC_MSG_NOTICE([LIBARGUS_PEP_LIBS=$LIBARGUS_PEP_LIBS])
    ],
    [
        AC_MSG_ERROR([Argus PEP client API (libargus-pep >= 2) not available. Check the PKG_CONFIG_PATH environment variable.])
    ]
)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h stdlib.h stdio.h stdint.h stdarg.h getopt.h pwd.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library and functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strerror strrchr calloc getpass])

# Sets default prefix
#AC_PREFIX_DEFAULT(/opt/emi)

AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([src/config.h])

AC_CONFIG_FILES([
Makefile
src/Makefile
])

AC_OUTPUT


