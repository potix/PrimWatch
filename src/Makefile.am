iSUBDIRS=src/test/src

YAJL_MAJOR = 2

sbin_PROGRAMS = primwatchd primwatch_primdns primwatch_powerdns
primwatchd_SOURCES = daemon_main.c string_util.c bhash.c config_manager.c json_parser.c shared_buffer.c watcher.c executor.c bson_helper.c bson/bson.c bson/encoding.c bson/numbers.c logger.c address_util.c controller.c tcp_server.c common_macro.h common_define.h config_manager.h bhash.h json_parser.h  string_util.h json_parser.h shared_buffer.h watcher.h executor.h bson_helper.h  bson/bson.h bson/encoding.h logger.h address_util.h common_struct.h controller.h tcp_server.h accessa.h
primwatchd_CFLAGS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wno-sign-compare -Wno-traditional -Wreturn-type -Wswitch -g3 -ggdb3 -pipe -Ibson -std=gnu99 -O2 -DYAJL_MAJOR=$(YAJL_MAJOR)
primwatchd_LDADD = -lyajl -levent

primwatch_primdns_SOURCES = accessa_main.c lookup.c bhash.c  shared_buffer.c bson_helper.c bson/bson.c bson/encoding.c bson/numbers.c logger.c dns/primdns.c address_util.c string_util.c common_macro.h common_define.h lookup.h bhash.h shared_buffer.h bson_helper.h bson/bson.h bson/encoding.h logger.h dns/primdns.h address_util.h string_util.h common_struct.h accessa.h
primwatch_primdns_CFLAGS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wno-sign-compare -Wno-traditional -Wreturn-type -Wswitch -g3 -ggdb3 -pipe -Ibson -Idns -std=gnu99 -O2 -DPRIMDNS

primwatch_powerdns_SOURCES = accessa_main.c lookup.c bhash.c  shared_buffer.c bson_helper.c bson/bson.c bson/encoding.c bson/numbers.c logger.c dns/powerdns.c address_util.c string_util.c common_macro.h common_define.h lookup.h bhash.h shared_buffer.h bson_helper.h bson/bson.h bson/encoding.h logger.h dns/powerdns.h address_util.h string_util.h common_struct.h accessa.h
primwatch_powerdns_CFLAGS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wno-sign-compare -Wno-traditional -Wreturn-type -Wswitch -g3 -ggdb3 -pipe -Ibson -Idns -std=gnu99 -O2 -DPOWERDNS

EXTRA_DIST = conf rc rc test

