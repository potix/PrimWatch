# rpmbuild spec

#######  defines  ###########
%{!?package_name: %define package_name primwatch}
%{!?package_version: %define package_version SNAPSHOT}
%{!?install_prefix: %define install_prefix /usr/local}
#############################

Name:		%{package_name}
Version:	%{package_version}
Release:	1%{?dist}
Summary:	%{package_name}
Group:		Etc
License:	Etc
URL:		https://github.com/potix/PrimWatch
Source0:	%{package_name}-%{package_version}.tar.gz
Source1:	scripts.tar.gz
BuildRequires:	libevent-devel yajl-devel
Requires:	libevent yajl

%description
 Check system helth and dynamic generate record of DNS with PrimDNS or PowerDNS

%prep 
tar -zxvf %{SOURCE0}
tar -zxvf %{SOURCE1} 

%build
cd %{package_name}-%{package_version}
./configure --prefix=%{install_prefix}/%{package_name}-%{package_version}
make
cd ..

%install
# directory
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/logs/%{package_name}"
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/tmp"
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/run"
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/%{package_name}-%{package_version}/bin"
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/%{package_name}-%{package_version}/sbin"
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/%{package_name}-%{package_version}/etc"
mkdir -p "${RPM_BUILD_ROOT}/etc/init.d"
mkdir -p "${RPM_BUILD_ROOT}/etc/sysconfig"

# install
cd %{package_name}-%{package_version} 
make install DESTDIR=%{buildroot}
cp "%{_builddir}/scripts/healthcheck/healthcheck.py" "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}-%{package_version}/bin/"
cp "%{_builddir}/scripts/conf/config.json" "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}-%{package_version}/etc/healthcheck.conf"
cp "%{_builddir}/%{package_name}-%{package_version}/src/primwatchd" "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}-%{package_version}/sbin/"
cp "%{_builddir}/%{package_name}-%{package_version}/src/primwatch_powerdns" "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}-%{package_version}/sbin/"
cp "%{_builddir}/%{package_name}-%{package_version}/src/primwatch_primdns" "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}-%{package_version}/sbin/"
cp "%{_builddir}/%{package_name}-%{package_version}/src/conf/primwatchd.conf" "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}-%{package_version}/etc/"
ln -sf %{install_prefix}/%{package_name}-%{package_version} "$RPM_BUILD_ROOT%{install_prefix}/%{package_name}"
cp "%{_builddir}/%{package_name}-%{package_version}/src/rc/primwatchd.init.sh" "$RPM_BUILD_ROOT/etc/init.d/primwatchd"
cp "%{_builddir}/%{package_name}-%{package_version}/src/rc/primwatchd.sysconfig" "$RPM_BUILD_ROOT/etc/sysconfig/primwatchd"

%files
%defattr(0755,root,root,-)
%{install_prefix}/%{package_name}-%{package_version}/bin
%{install_prefix}/%{package_name}-%{package_version}/sbin
/etc/init.d/primwatchd
%defattr(0644,root,root,-)
%{install_prefix}/tmp
%{install_prefix}/logs
%{install_prefix}/run
%{install_prefix}/%{package_name}-%{package_version}/etc
%{install_prefix}/%{package_name}
/etc/sysconfig/primwatchd

%doc
# do nothing

%clean
rm -rf "${RPM_BUILD_ROOT}"
rm -rf "%{_builddir}"

%changelog
* Mon Oct 20 2014 Hiroyuki Kakine <poti.dog@gmail.com> 0.1
  - first package version 0.1


