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

AC_INIT(glite-authz-pep-c-cli, 1.3.0, grid@switch.ch)
AC_CONFIG_AUX_DIR(project)

# OSX requires ./configure --disable-dependency-tracking to compile, others don't care
AM_INIT_AUTOMAKE([no-dependencies])
# disable static library
AM_DISABLE_STATIC

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC
#AC_PROG_MKDIR_P # not defined on SL4 !!!
AC_PROG_INSTALL
AC_PROG_LN_S

# Check for doxygen
AC_CHECK_PROG(DOXYGEN,doxygen,doxygen,$ac_aux_dir/missing --run doxygen)
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

# bootstrap glite.m4 (--with-glite-location=/opt/glite)
AC_GLITE
AC_MSG_NOTICE([libdir for $host: $libdir])

# Checks for PEP-C headers and library
# will automatically add -lpep-c in LDFLAGS
CFLAGS="$CFLAGS $GLITE_CFLAGS"
AC_MSG_NOTICE([CFLAGS=$CFLAGS])
LDFLAGS="$LDFLAGS $GLITE_LDFLAGS"
AC_MSG_NOTICE([LDFLAGS=$LDFLAGS])
AC_CHECK_HEADER([pep/pep.h],,[AC_MSG_ERROR(can not find pep-c library header)])
AC_CHECK_LIB(pep-c,pep_initialize)
AC_CHECK_LIB(pep-c,pep_version)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h stdlib.h stdio.h stdint.h stdarg.h getopt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# FUCK!!! int32_t and int64_t macro not available on SLC4
#AC_TYPE_INT32_T
#AC_TYPE_INT64_T

# Checks for library and functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strerror strrchr calloc])

# Sets default prefix
AC_PREFIX_DEFAULT(/opt/glite)

AC_CONFIG_SRCDIR(src)
AM_CONFIG_HEADER(src/config.h)

AC_CONFIG_FILES([
Makefile
src/Makefile
])

AC_OUTPUT

