Name: argus-pepcli

Version: 2.1.1
Release: 1%{?dist}
Summary: Argus pepcli command line


License: ASL 2.0
Group: Development/Tools
URL: https://twiki.cern.ch/twiki/bin/view/EGEE/AuthorizationFramework

Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: argus-pep-api-c-devel

%description
Argus PEP client command line interface: pepcli

The Argus PEP client command line interface is used to communicate 
with the Argus PEP Server. It authorizes request and receives 
authorization response back from Argus.

%prep
%setup -q

%build
%configure

# The following two lines were suggested by
# https://fedoraproject.org/wiki/Packaging/Guidelines to prevent any
# RPATHs creeping in.
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install
strip -s -v %{buildroot}%{_bindir}/pepcli


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_bindir}/pepcli
%{_mandir}/man1/pepcli.1.gz
%doc AUTHORS COPYRIGHT LICENSE README INSTALL CHANGELOG

%changelog
* Fri Aug 3 2012 Valery Tschopp <valery.tschopp@switch.ch> 2.1.1-1
- Self managed managed packaging with spec file.

* Tue Apr 3 2012 Valery Tschopp <valery.tschopp@switch.ch> 2.1.0-2
- Initial Argus pepcli command  for EMI 2.



