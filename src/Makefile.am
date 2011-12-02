#
# Copyright 2008 Members of the EGEE Collaboration.
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
# $Id: Makefile.am 1299 2009-10-15 15:29:34Z vtschopp $
#

SUBDIRS = util
AM_CPPFLAGS = -I$(top_srcdir)/src/util

#
# PEP-C client CLI exec
#
bin_PROGRAMS = pepcli

pepcli_SOURCES = \
    pepcli.c \
    log.c

pepcli_CFLAGS = \
    $(LIBARGUS_PEP_CFLAGS)
    
#pepcli_LDFLAGS =

pepcli_LDADD = \
    $(LIBARGUS_PEP_LIBS)

# man page
mandir = $(datadir)/man
man1_MANS = pepcli.1
