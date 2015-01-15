VERSION=0.3
PACKAGE=primwatch
SUBDIRS=src 

test: all
	src/test/src/address_util_test
	src/test/src/bhash_test
	src/test/src/command_test
	src/test/src/string_util_test
	src/test/src/config_test src/test/conf/primwatchd.conf
	bash src/test/test.sh src/test

rpm: dist
	tar -zcvf scripts.tar.gz scripts
	(cd rpm && make) || exit 1

rpmclean: 
	(cd rpm && make clean) || exit 1
