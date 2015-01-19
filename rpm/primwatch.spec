# rpmbuild spec

#######  defines  ###########
%{!?package_name: %define package_name primwatch}
%{!?package_version: %define package_version SNAPSHOT}
%{!?install_prefix: %define install_prefix /usr/local}
%{!?sysconf_install_prefix: %define sysconf_install_prefix /}
#############################

Name:		%{package_name}
Version:	%{package_version}
Release:	1%{?dist}
Summary:	backend software of dns server
Group:          System Environment
License:        BSD
Vendor:         Hiroyuki Kakine <poti.dog@gmail.com>
Packager:       Hiroyuki Kakine <poti.dog@gmail.com>
URL:		https://github.com/potix/PrimWatch
Source0:	%{package_name}-%{package_version}.tar.gz
Source1:	scripts.tar.gz
BuildRequires:	libevent-devel yajl-devel
Requires:	libevent yajl
Prefix:         /

%description
 Check system helth and dynamic generate record of DNS with PrimDNS or PowerDNS

%prep 
tar -zxvf %{SOURCE0}
tar -zxvf %{SOURCE1} 

%build
cd %{package_name}-%{package_version}
./configure --prefix=$RPM_BUILD_ROOT%{install_prefix} --sysconfdir=$RPM_BUILD_ROOT%{sysconf_install_prefix}/etc/primwatch
make
cd ..

%install
# directory
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/bin"
mkdir -p "${RPM_BUILD_ROOT}%{install_prefix}/sbin"
mkdir -p "${RPM_BUILD_ROOT}%{sysconf_install_prefix}/etc/init.d"
mkdir -p "${RPM_BUILD_ROOT}%{sysconf_install_prefix}/etc/sysconfig"
mkdir -p "${RPM_BUILD_ROOT}%{sysconf_install_prefix}/etc/%{package_name}"

# install
cd "%{_builddir}/%{package_name}-%{package_version}"
make install
install -c -m 755 "%{_builddir}/scripts/healthcheck/healthcheck.py" "$RPM_BUILD_ROOT%{install_prefix}/bin/healthcheck.py"
install -c -m 644 "%{_builddir}/scripts/conf/config.json" "$RPM_BUILD_ROOT%{sysconf_install_prefix}/etc/%{package_name}/healthcheck.conf"
install -c -m 644 "%{_builddir}/%{package_name}-%{package_version}/src/conf/primwatchd.conf" "$RPM_BUILD_ROOT%{sysconf_install_prefix}/etc/%{package_name}/primwatchd.conf"
install -c -m 755 "%{_builddir}/%{package_name}-%{package_version}/src/rc/primwatchd.init.sh" "$RPM_BUILD_ROOT%{sysconf_install_prefix}/etc/init.d/primwatchd"
install -c -m 644 "%{_builddir}/%{package_name}-%{package_version}/src/rc/primwatchd.sysconfig" "$RPM_BUILD_ROOT%{sysconf_install_prefix}/etc/sysconfig/primwatchd"

%files
%defattr(0755,root,root,-)
%{install_prefix}/bin
%{sysconf_install_prefix}/etc/init.d/primwatchd
%defattr(0644,root,root,-)
%config(noreplace) %{sysconf_install_prefix}/etc/sysconfig/primwatchd
%config(noreplace) %{sysconf_install_prefix}/etc/%{package_name}

%doc
# do nothing

%clean
rm -rf "${RPM_BUILD_ROOT}"
rm -rf "%{_builddir}"

%changelog
* Thu Jan 19 2015 Hiroyuki Kakine <poti.dog@gmail.com> 0.3
  - fix busy loop bug
  - split to log file
  - adjust log
* Tue Dec 2 2014 Hiroyuki Kakine <poti.dog@gmail.com> 0.2
  - fix logging
  - fix taking over status
* Mon Oct 20 2014 Hiroyuki Kakine <poti.dog@gmail.com> 0.1
  - first package version 0.1

