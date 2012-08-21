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

SUBDIRS = src 
EXTRA_DIST = AUTHORS ChangeLog LICENSE COPYRIGHT autotools.sh fedora debian

docdir = $(datadir)/doc/$(PACKAGE_NAME)-$(PACKAGE_VERSION)
doc_DATA = AUTHORS ChangeLog LICENSE COPYRIGHT

# Generate doxygen doc
doxygen: doc/Doxyfile
	$(DOXYGEN) doc/Doxyfile

#
# RPM/ETICS
#
name = argus-pepcli
version = $(PACKAGE_VERSION)
release = 1

spec_file = fedora/$(name).spec
rpmbuild_dir = $(CURDIR)/rpmbuild
debbuild_dir = $(CURDIR)/debbuild

clean-local:
	@echo "Cleaning..."
	rm -fr rpmbuild debbuild tgz RPMS target *.tar.gz 


spec:
	@echo "Setting version and release in spec file: $(version)-$(release)"
	sed -e 's#@@SPEC_VERSION@@#$(version)#g' -e 's#@@SPEC_RELEASE@@#$(release)#g' $(spec_file).in > $(spec_file)


rpm: spec
	test -f $(name)-$(version).tar.gz || make dist
	@echo "Building RPM with $(spec_file)"
	mv $(name)-$(version).tar.gz $(name)-$(version).src.tar.gz
	mkdir -p $(rpmbuild_dir)/BUILD $(rpmbuild_dir)/RPMS $(rpmbuild_dir)/SOURCES $(rpmbuild_dir)/SPECS $(rpmbuild_dir)/SRPMS
	cp $(name)-$(version).src.tar.gz $(rpmbuild_dir)/SOURCES/$(name)-$(version).tar.gz
	rpmbuild -v -ba $(spec_file) --define "_topdir $(rpmbuild_dir)"


deb:
	test -f $(name)-$(version).tar.gz || make dist
	@echo "Building Debian package in $(debbuild_dir)"
	mv $(name)-$(version).tar.gz $(name)-$(version).src.tar.gz
	mkdir -p $(debbuild_dir)
	cp $(name)-$(version).src.tar.gz $(debbuild_dir)/$(name)_$(version).orig.tar.gz
	tar -C $(debbuild_dir) -xf $(name)-$(version).src.tar.gz
	cd $(debbuild_dir)/$(name)-$(version) && debuild -us -uc 


etics: 
	@echo "Publishing RPMs and tarballs"
	mkdir -p RPMS tgz
	test -f $(rpmbuild_dir)/SRPMS/$(name)-$(version)-*.src.rpm
	cp -r $(rpmbuild_dir)/RPMS/* $(rpmbuild_dir)/SRPMS/* RPMS
	test -f $(name)-$(version).src.tar.gz && cp $(name)-$(version).src.tar.gz tgz
	test ! -f $(name)-$(version).bin.tar.gz || cp $(name)-$(version).bin.tar.gz tgz/$(name)-$(version).tar.gz


