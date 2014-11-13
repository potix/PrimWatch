VERSION=0.1
PACKAGE=primwatch
SUBDIRS = src

test: all
	src/test/src/address_util_test
	src/test/src/bhash_test
	src/test/src/command_test
	src/test/src/string_util_test

rpm: dist
	tar -zcvf scripts.tar.gz scripts
	(cd rpm && make) || exit 1

rpmclean: 
	(cd rpm && make clean) || exit 1
