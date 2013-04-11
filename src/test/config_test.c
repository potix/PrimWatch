#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "bson/bson.h"
#include "common_macro.h"
#include "bson_helper.h"
#include "config_manager.h"

static int group_foreach_cb(void *foreach_arg, const char *path, bson_iterator *itr) {
	bson *config = foreach_arg; 
	bson_type bson_type;
	const char *key;
	int64_t l;
	int b;
	const char *s;
	char p[2048];

        bson_type = bson_iterator_type(itr);
	ASSERT(bson_type == BSON_OBJECT);
	key = bson_iterator_key(itr);
        printf("group.%s\n", key);
	ASSERT(bson_helper_itr_get_long(itr, &l, "maxRecords", config, "defaultMaxRecords") == 0);
        ASSERT(l == 3);
	snprintf(p, sizeof(p), "%s.maxRecords", key);
	ASSERT(bson_helper_itr_get_long(itr, &l, p, config, "defaultMaxRecords") == 0);
        ASSERT(l == 2);
        printf("group.%s.maxRecords - %lld\n", key, (long long)l);
	snprintf(p, sizeof(p), "%s.recordSelectAlgorithm", key);
	ASSERT(bson_helper_itr_get_string(itr, &s, p, NULL, NULL) == 0);
        ASSERT(strcmp(s, "ransom"));
        printf("group.%s.recoedSelectAlgorithm - %s\n", key, s);
	snprintf(p, sizeof(p), "%s.recordPreempt", key);
	ASSERT(bson_helper_itr_get_bool(itr, &b, p, config, "defaultRecordPreempt") == 0);
        ASSERT(b == 1);
        printf("group.%s.recoedPreempt - %d\n", key ,b);
	snprintf(p, sizeof(p), "%s.NGgroupPriority", key);
	ASSERT(bson_helper_itr_get_long(itr, &l, p, config, "NGdefaultGroupPriority") == 1);

	return BSON_HELPER_FOREACH_SUCCESS;
}

int
main(int argc, char*argv[])
{
	config_manager_t *config_manager;
	bson *config;
	bson_iterator itr;
	const char *s;

	ASSERT(config_manager_create(&config_manager) == 0);
	ASSERT(config_manager_load(config_manager, "../primwatch.conf") == 0);
	ASSERT(config_manager_dump(config_manager) == 0);
	ASSERT(config_manager_load(config_manager, "../primwatch.conf") == 0);
	ASSERT(config_manager_dump(config_manager) == 0);
	ASSERT(config_manager_get_config(config_manager, &config) == 0);
	ASSERT(bson_helper_bson_get_itr(&itr, config, "groups") == 0);
	ASSERT(bson_helper_bson_get_string(config, &s, "defaultRecordSelectAlgorithm", NULL) == 0);
	ASSERT(strcmp(s, "random") == 0);
	ASSERT(bson_helper_bson_get_string(config, &s, "groupSelectOrder", "logType") == 0);
	ASSERT(strcmp(s, "domainRemoteAddress") == 0);
	ASSERT(bson_helper_bson_get_string(config, &s, "NGlogType", "logType") == 0);
	ASSERT(strcmp(s, "syslog") == 0);
	ASSERT(bson_helper_bson_get_string(config, &s, "NGlogType", "NGlogType") == 1);
	ASSERT(bson_helper_itr_foreach(&itr, ".", group_foreach_cb, config) == 0);
	ASSERT(config_manager_destroy(config_manager) == 0);
	printf("success\n");

	return 0;
}
