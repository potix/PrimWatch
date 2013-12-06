#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "common_macro.h"
#include "common_define.h"
#include "json_parser.h"
#include "config_manager.h"
#include "bson_helper.h"
#include "address_util.h"
#include "logger.h"

#define DEFAULT_MAX_SHARED_BUFFER_SIZE	      (64 * 1024 * 1024) 
#define DEFAULT_SHARED_BUFFER_FILE	      "/var/tmp/primwatchd.mem"
#define DEFAULT_LOG_TYPE		      "syslog"
#define DEFAULT_LOG_FACILITY		      "daemon"
#define DEFAULT_LOG_PATH		      "/var/log/primwatch.log"
#define DEFAULT_PID_FILE_PATH		      "/var/run/primwatchd.pid"
#define DEFAULT_VERBOSE_LEVEL	  	      7
#define DEFAULT_GROUP_SELECT_ORDER  	      "domainRemoteAddress"
#define DEFAULT_GROUP_SELECT_ORDER_VALUE      0
#define DEFAULT_GROUP_SELECT_ALGORITHM        "random"
#define DEFAULT_GROUP_SELECT_ALGORITHM_VALUE  0
#define DEFAULT_GROUP_PREEMPT		      1  
#define DEFAULT_POLLING_INTERVAL	      5
#define DEFAULT_GROUP_PRIORITY		      1000
#define DEFAULT_GROUP_WEIGHT		      1000
#define DEFAULT_MAX_FORWARD_RECORDS	      3
#define DEFAULT_MAX_REVERSE_RECORDS	      1 
#define DEFAULT_RECORD_SELECT_ALGORITHM      "random"
#define DEFAULT_RECORD_SELECT_ALGORITHM_VALUE 0
#define DEFAULT_RECORD_PREEMPT		      1
#define DEFAULT_RECORD_STATUS		      "down"
#define DEFAULT_RECORD_TTL		      DEFAULT_POLLING_INTERVAL
#define DEFAULT_RECORD_PRIORITY		      1000
#define DEFAULT_RECORD_WEIGHT		      1000

struct config_manager {
	json_parser_t *json_parser;
	bson *config;
};

static const char *log_type_candidate[] = {
	"file",
	"syslog",
	"stderr",
	"stdout",
	NULL
};

static const char *group_select_order_candidate[] = {
	"domainRemoteAddress",  /* 0 */
	"remoteAddressDomain",  /* 1 */
	NULL
};

static const char *group_select_algorithm_candidate[] = {
	"random",     /* 0 */
	"priority",   /* 1 */
	"roundRobin", /* 2 */
	"weight",     /* 3 */
	NULL
};

static const char *record_select_algorithm_candidate[] = {
	"random",     /* 0 */
	"priority",   /* 1 */
	"roundRobin", /* 2 */
	"weight",     /* 3 */
	NULL
};

static const char *record_status_candidate[] = {
	"up",
	"down",
	NULL
};

static int config_manager_init_validation(json_parser_t *json_parser);
static int config_init(bson *config);
static int config_finish(bson *config);
static int config_manager_append_value(
    void *validate_callback_arg,
    const char *path,
    const char *key,
    const char *s,
    size_t len,
    bson *bson);
static int config_manager_append_addrmask(
    void *validate_callback_arg,
    const char *path,
    const char *key,
    const char *s,
    size_t len,
    bson *bson);

static int
config_manager_append_value(
    void *validate_callback_arg,
    const char *path,
    const char *key,
    const char *s,
    size_t len,
    bson *bson)
{
	int i;

	if (strcmp(key, "groupSelectOrder") == 0) {
		for (i = 0; group_select_order_candidate[i] != NULL; i++) {
			if (strcmp(group_select_order_candidate[i], s) != 0) {
				continue;
			}
			if (bson_append_long(bson, "groupSelectOrderValue", (long)i) != BSON_OK) {
				LOG(LOG_LV_ERR, "failed in append value of group select order to bson");
				goto fail;
			}
			break;
		}
		ASSERT(group_select_order_candidate[i] != NULL);
	} else if (strcmp(key, "groupSelectAlgorithm") == 0) {
		for (i = 0; group_select_algorithm_candidate[i] != NULL; i++) {
			if (strcmp(group_select_algorithm_candidate[i], s) != 0) {
				continue;
			}
			if (bson_append_long(bson, "groupSelectAlgorithmValue", (long)i) != BSON_OK) {
				LOG(LOG_LV_ERR, "failed in append value of group select algorithm to bson");
				goto fail;
			}
			break;
		}
		ASSERT(group_select_algorithm_candidate[i] != NULL);
	} else if (strcmp(key, "defaultRecordSelectAlgorithm") == 0) {
		for (i = 0; record_select_algorithm_candidate[i] != NULL; i++) {
			if (strcmp(record_select_algorithm_candidate[i], s) != 0) {
				continue;
			}
			if (bson_append_long(bson, "defaultRecordSelectAlgorithmValue", (long)i) != BSON_OK) {
				LOG(LOG_LV_ERR, "failed in append value of default record select algorithm to bson");
				goto fail;
			}
			break;
		}
		ASSERT(record_select_algorithm_candidate[i] != NULL);
	} else if (strcmp(key, "recordSelectAlgorithm") == 0) {
		for (i = 0; record_select_algorithm_candidate[i] != NULL; i++) {
			if (strcmp(record_select_algorithm_candidate[i], s) != 0) {
				continue;
			}
			if (bson_append_long(bson, "recordSelectAlgorithmValue", (long)i) != BSON_OK) {
				LOG(LOG_LV_ERR, "failed in append value of record select algorithm to bson");
				goto fail;
			}
			break;
		}
		ASSERT(record_select_algorithm_candidate[i] != NULL);
	} else {
		/* NOTREACHED */
		ABORT("unexpected key");
		goto fail;
	}

	return JSON_PARSER_VALIDATION_SUCCESS;
fail:

	return JSON_PARSER_VALIDATION_ERROR;
}

static int
config_manager_append_addrmask(
    void *validate_callback_arg,
    const char *path,
    const char *key,
    const char *s,
    size_t len,
    bson *bson)
{
	v4v6_addr_mask_t addr_mask;

	ASSERT(strcmp(key, "address") == 0);
	if (addrstr_to_addrmask(&addr_mask, s)) {
		LOG(LOG_LV_ERR, "failed in convert address and mask (%s)", s);
		goto fail;
	}
	if (bson_append_binary(bson, "addressAndMask", BSON_BIN_BINARY, (const char *)&addr_mask, sizeof(v4v6_addr_mask_t)) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append address and mask to bson", s);
		goto fail;
	}

	return JSON_PARSER_VALIDATION_SUCCESS;
fail:

	return JSON_PARSER_VALIDATION_ERROR;
}

static int
config_manager_init_validation(json_parser_t *json_parser)
{
	if (json_parser_add_validation_integer(json_parser, "^maxSharedBufferSize$", 8192, (1024 * 1024 * 1024), NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^logType$", 4, 6, log_type_candidate, 4, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^logFacility$", 1, MAXPATHLEN, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^logPath$", 1, MAXPATHLEN, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^pidFilePath$", 1, MAXPATHLEN, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^verboseLevel$", 0, 9, NULL, NULL)) {
		return 1;
	}
        if (json_parser_add_validation_string(json_parser, "^groupSelectOrder$", 19, 19, group_select_order_candidate, 2, config_manager_append_value, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^groupSelectAlgorithm$", 6, 10, group_select_algorithm_candidate, 4, config_manager_append_value, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_boolean(json_parser, "^groupPreempt$", NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultPollingInterval$", 1, 86400, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultGroupPriority$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultGroupWeight$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultMaxForwardRecords$", 1, 64, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultMaxReverseRecords$", 1, 64, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^defaultRecordSelectAlgorithm$", 6, 10, record_select_algorithm_candidate, 4, config_manager_append_value, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_boolean(json_parser, "^defaultRecordPreempt$", NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^defaultRecordStatus$", 2, 4, record_status_candidate, 2, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultRecordTtl$", 1, 2592000, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultRecordPriority$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^defaultRecordWeight$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^domainMap\\.pollingInterval$", 1, 86400, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^domainMap\\.executeScript$", 1, MAXPATHLEN, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^remoteAddressMap\\.pollingInterval$", 1, 86400, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^remoteAddressMap\\.executeScript$", 1, MAXPATHLEN, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^healthCheck\\.pollingInterval$", 1, 86400, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^healthCheck\\.executeScript$", 1, MAXPATHLEN, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]+\\.maxForwardRecords$", 1, MAX_RECORDS, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]+\\.maxReverseRecords$", 1, MAX_RECORDS, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^groups\\.[^.]+\\.recordSelectAlgorithm$", 6, 10, record_select_algorithm_candidate, 4, config_manager_append_value, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_boolean(json_parser, "^groups\\.[^.]+\\.recordPreempt$", NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]+\\.groupPriority$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]+\\.groupWeight$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_boolean(json_parser, "^groups\\.[^.]+\\.forceDown$", NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^groups\\.[^.]+\\.forwardRecords\\.[0-9]+\\.hostname$", 1, NI_MAXHOST, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^groups\\.[^.]+\\.forwardRecords\\.[0-9]+\\.address$", 7, INET_ADDRSTRLEN, NULL, 0, config_manager_append_addrmask, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]+\\.forwardRecords\\.[0-9]+\\.recordPriority$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]\\.forwardRecords\\.[0-9]+\\.recordWeight$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]\\.forwardRecords\\.[0-9]+\\.ttl$", 1, 2592000, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_boolean(json_parser, "^groups\\.[^.]\\.forwardRecords\\.[0-9]+\\.forceDown$", NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^groups\\.[^.]+\\.reverseRecords\\.[0-9]+\\.hostname$", 1, NI_MAXHOST, NULL, 0, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_string(json_parser, "^groups\\.[^.]+\\.reverseRecords\\.[0-9]+\\.address$", 7, INET_ADDRSTRLEN, NULL, 0, config_manager_append_addrmask, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]+\\.reverseRecords\\.[0-9]+\\.recordPriority$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]\\.reverseRecords\\.[0-9]+\\.recordWeight$", 1, 65535, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_integer(json_parser, "^groups\\.[^.]\\.reverseRecords\\.[0-9]+\\.ttl$", 1, 2592000, NULL, NULL)) {
		return 1;
	}
	if (json_parser_add_validation_boolean(json_parser, "^groups\\.[^.]\\.reverseRecords\\.[0-9]+\\.forceDown$", NULL, NULL)) {
		return 1;
	}

	return 0;
}

static int
config_init(bson *config)
{
	bson_init(config);

	return 0;
}

static int
config_finish(bson *config)
{
	int members_count = 0;

	if (bson_helper_bson_get_len(config, "groups", &members_count)) {
		return 1;
	}
	if (members_count == 0) {
		LOG(LOG_LV_ERR, "not found group");
		return 1;
	}
	if (bson_append_long(config, "groupMembersCount", (int64_t)members_count) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "maxSharedBufferSize", DEFAULT_MAX_SHARED_BUFFER_SIZE) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "logType", DEFAULT_LOG_TYPE) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "logFacility", DEFAULT_LOG_FACILITY) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "logPath", DEFAULT_LOG_PATH) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "pidFilePath", DEFAULT_PID_FILE_PATH) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "verboseLevel",  DEFAULT_VERBOSE_LEVEL) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "groupSelectOrder", DEFAULT_GROUP_SELECT_ORDER) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "groupSelectOrderValue", DEFAULT_GROUP_SELECT_ORDER_VALUE) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "groupSelectAlgorithm", DEFAULT_GROUP_SELECT_ALGORITHM) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "groupSelectAlgorithmValue", DEFAULT_GROUP_SELECT_ALGORITHM_VALUE) != BSON_OK) {
		return 1;
	}
	if (bson_append_bool(config, "groupPreempt", DEFAULT_GROUP_PREEMPT) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultPollingInterval", DEFAULT_POLLING_INTERVAL) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultGroupPriority", DEFAULT_GROUP_PRIORITY) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultGroupWeight", DEFAULT_GROUP_WEIGHT) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultMaxForwardRecords", DEFAULT_MAX_FORWARD_RECORDS) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultMaxReverseRecords", DEFAULT_MAX_REVERSE_RECORDS) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "defaultRecordSelectAlgorithm", DEFAULT_RECORD_SELECT_ALGORITHM) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultRecordSelectAlgorithmValue", DEFAULT_RECORD_SELECT_ALGORITHM_VALUE) != BSON_OK) {
		return 1;
	}
	if (bson_append_bool(config, "defaultRecordPreempt", DEFAULT_RECORD_PREEMPT) != BSON_OK) {
		return 1;
	}
	if (bson_append_string(config, "defaultRecordStatus", DEFAULT_RECORD_STATUS) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultRecordTtl", DEFAULT_RECORD_TTL) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultRecordPriority", DEFAULT_RECORD_PRIORITY) != BSON_OK) {
		return 1;
	}
	if (bson_append_long(config, "defaultRecordWeight", DEFAULT_RECORD_WEIGHT) != BSON_OK) {
		return 1;
	}
	if (bson_finish(config) != BSON_OK) {
		return 1;
	}

	return 0;
}

int
config_manager_create(
    config_manager_t **config_manager)
{
	config_manager_t *new = NULL;
	json_parser_t *json_parser = NULL;

	if (config_manager == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(config_manager_t));
	if (new == NULL) {
		return ENOBUFS;
	}
	memset(new, 0, sizeof(config_manager_t));
	if (json_parser_create(&json_parser)) {
		goto fail;
	}
	if (config_manager_init_validation(json_parser)) {
		goto fail;
	}
	new->json_parser = json_parser;
	*config_manager = new;
	
	return 0;

fail:

	if (json_parser) {
		json_parser_destroy(json_parser);
	}
	free(new);

	return 1;
}

int
config_manager_destroy(
    config_manager_t *config_manager)
{
	if (config_manager == NULL) {
		errno = EINVAL;
		return 1;
	}
	json_parser_destroy(config_manager->json_parser);
	if (config_manager->config) {
		bson_destroy(config_manager->config);
		bson_dealloc(config_manager->config);
	}
	free(config_manager);

	return 0;
}

int
config_manager_load(
    config_manager_t *config_manager,
    const char *config_file_path)
{
	bson *old_config, *new_config = NULL;

	if (config_manager == NULL ||
	    config_file_path == NULL) {
		errno = EINVAL;
		return 1;
	}
	new_config = bson_alloc();
	if (new_config == NULL) {
		return ENOBUFS;
	}
	if (config_init(new_config)) {
		goto fail;
	}
	if (json_parser_parse(
	    config_manager->json_parser,
	    config_file_path,
	    new_config)) {
		LOG(LOG_LV_ERR, "failed in parse json (%s)", config_file_path);
		goto fail;
	}
	if (config_finish(new_config)) {
		goto fail;
	}
	old_config = config_manager->config;
	config_manager->config = new_config;
	if (old_config) {
		bson_destroy(old_config);
		bson_dealloc(old_config);
	}

	return 0;

fail:
	if (new_config) {
		bson_destroy(new_config);
		bson_dealloc(new_config);
	}

	return 1;
}

int
config_manager_dump(
    config_manager_t *config_manager)
{
	if (config_manager == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (config_manager->config == NULL) {
		return 0;
	}
	bson_print(config_manager->config);

	return 0;
}

int
config_manager_get_config(
    config_manager_t *config_manager,
    bson **config)
{
	if (config_manager == NULL ||
	    config == NULL) {
		errno = EINVAL;
		return 1;
	}
	*config = config_manager->config;

	return 0;
}

int
config_manager_get_string(
    config_manager_t *config_manager,
    char const **s,
    const char *path,
    const char *default_path)
{
	if (config_manager == NULL || s == NULL) {
		errno = EINVAL;
		return 1;
	}
	return bson_helper_bson_get_string(
	    config_manager->config,
            s,
            path,
            default_path);
}

int
config_manager_get_bool(
    config_manager_t *config_manager,
    int *b,
    const char *path,
    const char *default_path)
{
	if (config_manager == NULL || b == NULL) {
		errno = EINVAL;
		return 1;
	}
	return bson_helper_bson_get_bool(
	    config_manager->config,
            b,
            path,
            default_path);
}

int
config_manager_get_long(
    config_manager_t *config_manager,
    int64_t *l,
    const char *path,
    const char *default_path)
{
	if (config_manager == NULL || l == NULL) {
		errno = EINVAL;
		return 1;
	}
	return bson_helper_bson_get_long(
	    config_manager->config,
            l,
            path,
            default_path);
}

