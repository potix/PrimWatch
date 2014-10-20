VERSION=0.1
PACKAGE=primwatch
SUBDIRS = src

rpm: dist
	tar -zcvf scripts.tar.gz scripts
	(cd rpm && make) || exit 1

rpmclean: 
	(cd rpm && make clean) || exit 1
