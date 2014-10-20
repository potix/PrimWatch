SUBDIRS = src

rpm: dist
	tar -cvf scripts.tar.gz scripts
	(cd rpm && make) || exit 1

rpmclean: 
	(cd rpm && make clean) || exit 1
