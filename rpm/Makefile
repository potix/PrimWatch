PATH:=$(PATH):/usr/local/bin:/usr/bin:/bin
make?=make
package_name=primwatch
package_version=0.1
top_dir=$(shell pwd | sed 's/ /\\ /g')
rpm_path=$(top_dir)/RPMS/x86_64/
rpm_suffix=*.rpm

rpm:  ../${package_name}-${package_version}.tar.gz ../scripts.tar.gz
	mkdir -p $(top_dir)/SOURCES
	mkdir -p $(top_dir)/RPMS
	mkdir -p $(top_dir)/SRPMS
	mkdir -p $(top_dir)/BUILD
	mkdir -p $(top_dir)/BUILDROOT
	mkdir -p $(top_dir)/SPECS
	mkdir -p $(top_dir)/INSTALL
	cp $< SOURCES/
	rpmbuild -ba --define "_topdir $(top_dir)" --define "module_name $(package_name)" --define "module_version $(package_version)" $(package_name).spec

clean:
	rm -rf SOURCES RPMS SRPMS BUILD BUILDROOT SPECS INSTALL TMP
