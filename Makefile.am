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

SUBDIRS = src 
EXTRA_DIST = LICENSE CHANGELOG autotools.sh 

docdir = $(datadir)/doc/$(PACKAGE)
doc_DATA = AUTHORS CHANGELOG LICENSE

# Generate doxygen doc
doxygen: doc/Doxyfile
	$(DOXYGEN) doc/Doxyfile

