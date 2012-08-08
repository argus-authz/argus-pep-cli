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
EXTRA_DIST = AUTHORS CHANGELOG LICENSE COPYRIGHT autotools.sh 

docdir = $(datadir)/doc/$(PACKAGE_NAME)-$(PACKAGE_VERSION)
doc_DATA = AUTHORS CHANGELOG LICENSE COPYRIGHT

# Generate doxygen doc
doxygen: doc/Doxyfile
	$(DOXYGEN) doc/Doxyfile

#
# RPM/ETICS
#
name = argus-pepcli
spec_file = fedora/$(name).spec
version = $(shell grep "Version:" $(spec_file) | sed -e "s/Version://g" -e "s/[ \t]*//g")
release = 1
rpmbuild_dir = $(shell pwd)/rpmbuild
stage_dir = $(shell pwd)/stage
fakeroot_dir = $(shell pwd)/FAKEROOT

clean-local:
	$(RM) -fr rpmbuild stage tgz RPMS target FAKEROOT *.tar.gz

rpm: dist
	mv -v $(name)-$(version).tar.gz $(name)-$(version).src.tar.gz
	echo "Building RPM in $(rpmbuild_dir)"
	mkdir -p $(rpmbuild_dir)/BUILD $(rpmbuild_dir)/RPMS \
		$(rpmbuild_dir)/SOURCES $(rpmbuild_dir)/SPECS \
		$(rpmbuild_dir)/SRPMS
	cp -v $(name)-$(version).src.tar.gz $(rpmbuild_dir)/SOURCES/$(name)-$(version).tar.gz
	rpmbuild -v -ba $(spec_file) --define "_topdir $(rpmbuild_dir)"

binary-tarball:
	mkdir -p $(fakeroot_dir)
	make DESTDIR=$(fakeroot_dir) install
	cd $(fakeroot_dir) && tar -cvzf ../$(name)-$(version).bin.tar.gz *


etics: rpm
	echo "Publishing RPMs and tarballs"
	mkdir -p tgz RPMS
	cp -v $(name)-$(version).src.tar.gz tgz
	test -f $(name)-$(version).bin.tar.gz && cp -v $(name)-$(version).bin.tar.gz tgz/$(name)-$(version).tar.gz
	cp -rv $(rpmbuild_dir)/RPMS/* $(rpmbuild_dir)/SRPMS/* RPMS


