bin_PROGRAMS = primwatchd primwatch_primdns primwatch_powedns
primwatchd_SOURCES = daemon_main.c string_util.c bhash.c config_manager.c json_parser.c shared_buffer.c watcher.c executor.c bson_helper.c bson/bson.c bson/encoding.c bson/numbers.c logger.c address_util.c controller.c tcp_server.c common_macro.h common_define.h config_manager.h bhash.h json_parser.h  string_util.h json_parser.h shared_buffer.h watcher.h executor.h bson_helper.h  bson/bson.h bson/encoding.h logger.h address_util.h common_struct.h controller.h tcp_server.h
primwatchd_CFLAGS = -Wall -O3
primwatchd_LDADD = -lyajl -levent

primwatch_primdns_SOURCES = accessa_main.c lookup.c bhash.c  shared_buffer.c bson_helper.c bson/bson.c bson/encoding.c bson/numbers.c logger.c dns/primdns.c address_util.c string_util.c common_macro.h common_defile.h lookup.h bhash.h shared_buffer.h bson_helper.h bson/bson.h bson/encoding.h logger.h dns/primdns.h address_util.h string_util.h record.h
primwatch_primdns_CFLAGS = -Wall -O3 -DPRIMDNS 

primwatch_powedns_SOURCES = accessa_main.c lookup.c bhash.c  shared_buffer.c bson_helper.c bson/bson.c bson/encoding.c bson/numbers.c logger.c dns/primdns.c address_util.c string_util.c common_macro.h common_defile.h lookup.h bhash.h shared_buffer.h bson_helper.h bson/bson.h bson/encoding.h logger.h dns/primdns.h address_util.h string_util.h record.h
primwatch_powedns_CFLAGS = -Wall -O3 -DPOWERDNS
