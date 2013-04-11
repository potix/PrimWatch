#include <sys/param.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "bson/bson.h"

#include "common_macro.h"
#include "common_define.h"
#include "bhash.h"
#include "config_manager.h"
#include "shared_buffer.h"
#include "executor.h"
#include "watcher.h"
#include "string_util.h"
#include "address_util.h"
#include "bson_helper.h"
#include "record.h"
#include "logger.h"

#ifndef DEFAULT_IO_BUFFER_SIZE
#define DEFAULT_IO_BUFFER_SIZE 2048
#endif

#define MAX_RECORD_BUFFER (INET6_ADDRSTRLEN + NI_MAXHOST + sizeof(record_buffer_t) + 8)
#define ALIGN_SIZE(size) ((size) + 8 - ((size) & 7))

typedef enum watcher_target_type watcher_target_type_t;
typedef enum watcher_status_change watcher_status_change_t;
typedef struct watcher_health_check_element watcher_health_check_element_t;
typedef struct watcher_target watcher_target_t;
typedef struct group_foreach_cb_arg group_foreach_cb_arg_t;
typedef struct record_foreach_cb_arg record_foreach_cb_arg_t;
typedef struct root_copy_param root_copy_param_t;
typedef struct sub_copy_param sub_copy_param_t;

enum watcher_status_change {
        STATUS_CHANGE_KEEP_DOWN = 1,
        STATUS_CHANGE_DOWN_TO_UP,
        STATUS_CHANGE_UP_TO_DOWN,
        STATUS_CHANGE_KEEP_UP
};

enum watcher_target_type {
	TARGET_TYPE_DOMAIN_MAP = 1,
	TARGET_TYPE_REMOTE_ADDRESS_MAP,
	TARGET_TYPE_HEALTH_CHECK
};

struct watcher_health_check_element {
        watcher_status_change_t latest_status_change;
        int current_status;
        int valid;
};

struct watcher_target {
        watcher_target_type_t type;
	struct event event;
	struct timeval polling_interval;
	char remain_buffer[DEFAULT_IO_BUFFER_SIZE];
	size_t remain_buffer_len;
        bhash_t *elements;
        watcher_t *backptr;
};

struct watcher {
        watcher_target_t domain_map;
        watcher_target_t remote_address_map;
        watcher_target_t health_check;
	struct event update_check_event;
	struct timeval update_check_interval;
	int updated;
        shared_buffer_t *shared_buffer;
	executor_t *executor;
	struct event_base *event_base;
        config_manager_t *config_manager;
};

struct group_foreach_cb_arg {
	bson *status;
	bson *config;
        bhash_t *health_check;
	const char *default_record_status;
};

struct record_foreach_cb_arg {
	group_foreach_cb_arg_t *group_foreach_cb_arg;
	bhash_t *address;
	bhash_t *hostname;
	int preempt;
};

struct root_copy_param {
	bson_type bson_type;
	const char *path;
};

struct sub_copy_param {
	bson_type bson_type;
	const char *path;
	const char *default_path;
};

static struct root_copy_param root_copy_params[] = {
	{ BSON_LONG, "groupMembersCount" },
	{ BSON_STRING, "logType" },
	{ BSON_STRING, "logFacility" },
	{ BSON_STRING, "logPath" },
	{ BSON_LONG, "verboseLevel" },
	{ BSON_LONG, "groupSelectOrderValue" },
	{ BSON_LONG, "groupSelectAlgorithmValue" }
};

static struct sub_copy_param group_copy_params[] = {
	{ BSON_LONG, "maxRecords", "defaultMaxRecords" },
	{ BSON_LONG, "recordSelectAlgorithmValue", "defaultRecordSelectAlgorithmValue" },
	{ BSON_BOOL, "recordPreempt", "defaultRcordPreempt" },
	{ BSON_LONG, "groupPriority", "defaultGroupPriority" }
};

static int watcher_record_foreach_cb(
    void *record_foreach_cb_arg,
    const char *path,
    bson_iterator *itr);
static int watcher_group_foreach_cb(
    void *group_foreach_cb_arg,
    const char *path,
    bson_iterator *itr);
static int watcher_status_make(
    bson *status,
    size_t max_size,
    config_manager_t *config_manager,
    bhash_t *domain_map,
    bhash_t *remote_address_map,
    bhash_t *health_check);
static void watcher_status_clean(bson *status);
static void watcher_health_check_element_compare(
    void *replace_cb_arg,
    const char *key,
    size_t key_size,
    char *old_value,
    size_t old_value_size,
    char *new_value,
    size_t new_value_size);
static int watcher_update(watcher_t *watcher);
static int watcher_polling_common_add_element(
    watcher_target_type_t target_type,
    char *key,
    char *value,
    bhash_t *elements);
static int watcher_set_polling_common(
    watcher_t *watcher,
    watcher_target_type_t type);
static void watcher_polling_common_response(
    int fd,
    short ev,
    void *arg, 
    exec_flag_t *exec_flag);
static void watcher_polling_common(int fd, short ev, void *arg);
static int watcher_set_polling_update_check(watcher_t *watcher);
static void watcher_polling_update_check(int fd, short ev, void *arg);

static int
watcher_record_foreach_cb(
    void *record_foreach_cb_arg,
    const char *path,
    bson_iterator *itr)
{
	record_foreach_cb_arg_t *arg = record_foreach_cb_arg;
	bson *config;
	bhash_t *health_check;
	const char *default_record_status;
	char p[MAX_BSON_PATH_LEN];
	char entry_buffer[MAX_RECORD_BUFFER];
	record_buffer_t *entry;
	const char *idx;
	const char *addr;
	const char *host;
	size_t addr_size;
	size_t host_size;
	watcher_health_check_element_t *health_check_element;
	
	ASSERT(arg != NULL);
	ASSERT(arg->group_foreach_cb_arg != NULL);
	ASSERT(arg->group_foreach_cb_arg->config != NULL);
	ASSERT(arg->group_foreach_cb_arg->status != NULL);
	ASSERT(arg->group_foreach_cb_arg->health_check != NULL);
	ASSERT(arg->group_foreach_cb_arg->default_record_status != NULL);
	ASSERT(arg->address != NULL);
	ASSERT(arg->hostname != NULL);
	config = arg->group_foreach_cb_arg->config;
	health_check = arg->group_foreach_cb_arg->health_check;
	default_record_status = arg->group_foreach_cb_arg->default_record_status;
	entry = (record_buffer_t *)&entry_buffer[0];
	idx = bson_iterator_key(itr);

	snprintf(p, sizeof(p),  "%s.address", idx);
	if (bson_helper_itr_get_string(itr, &addr, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get address (index = %s)", idx);
		goto fail;
	}
	addr_size = strlen(addr) + 1;
	if (bhash_get(health_check, (char **)&health_check_element, NULL, addr, addr_size)) {
		LOG(LOG_LV_ERR, "failed in get health (index = %s)", idx);
		goto fail;
	}
	if (health_check_element == NULL) {
		if (strcasecmp(default_record_status, "up") != 0) {
			return BSON_HELPER_FOREACH_SUCCESS;
		}
	}
	/* update valid of health check flag if record preempt is enable */
	if (arg->preempt == 1 && health_check_element->current_status == 1 && health_check_element->valid == 0) {
		health_check_element->valid = 1;
	}
	if (health_check_element->current_status == 0 ||
	    health_check_element->valid == 0) {
		return BSON_HELPER_FOREACH_SUCCESS;
	}
	snprintf(p, sizeof(p),  "%s.hostname", idx);
	if (bson_helper_itr_get_string(itr, &host, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get hostname (index = %s)", idx);
		goto fail;
	}
	host_size = strlen(host) + 1;
	snprintf(p, sizeof(p),  "%s.ttl", idx);
	if (bson_helper_itr_get_long(itr, &entry->ttl, p, config, "defaultTtl")) {
		LOG(LOG_LV_ERR, "failed in get ttl (index = %s)", idx);
		goto fail;
	}
	snprintf(p, sizeof(p),  "%s.recordPriority", idx);
	if (bson_helper_itr_get_long(itr, &entry->record_priority, p, config, "defaultRecordPriority")) {
		LOG(LOG_LV_ERR, "failed in get record priority (index = %s)", idx);
		goto fail;
	}
	entry->value_size = host_size;
	memcpy(((char *)entry) + offsetof(record_buffer_t, value), host, host_size);
	if (bhash_append(arg->address,
	    addr,
	    addr_size,
	    (char *)entry,
	    sizeof(record_buffer_t) + entry->value_size)) {
		LOG(LOG_LV_ERR, "failed in append address (index = %s)", idx);
		goto fail;
	}
	entry->value_size = addr_size;
	memcpy(((char *)entry) + offsetof(record_buffer_t, value), addr, addr_size);
	if (bhash_append(arg->hostname,
	    host,
	    host_size,
	    (char *)entry,
	    sizeof(record_buffer_t) + entry->value_size)) {
		LOG(LOG_LV_ERR, "failed in append hostname (index %s)", idx);
		goto fail;
	}

	return BSON_HELPER_FOREACH_SUCCESS;

fail:
	/*
         * not return BSON_HELPER_FOREACH_ERROR
         * then, skip record entry
         */ 
	return BSON_HELPER_FOREACH_SUCCESS;
}

static int
watcher_group_foreach_cb(
    void *group_foreach_cb_arg,
    const char *path,
    bson_iterator *itr)
{
	int i;
	group_foreach_cb_arg_t *arg = group_foreach_cb_arg;
	record_foreach_cb_arg_t record_foreach_cb_arg;
	bson *config;
	bson *status;
	const char *name;
	int64_t l;
	int b;
	int preempt;
	const char *s;
	char p[MAX_BSON_PATH_LEN];
	int group_object_start = 0;
	bhash_t *address = NULL, *hostname = NULL;
	char *bhash_data;
	size_t bhash_data_size;
	int record_member_count;

	ASSERT(arg != NULL);
	ASSERT(arg->config != NULL);
	ASSERT(arg->status != NULL);
	ASSERT(arg->health_check != NULL);
	ASSERT(arg->default_record_status != NULL);
	config = arg->config;
	status = arg->status;
	name = bson_iterator_key(itr);
        if (bson_append_start_object(status, name) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in start group entry object (group %s)", name);
                goto fail;
        }
	group_object_start = 1;
	if (bson_helper_itr_get_bool(itr, &preempt, "recordPreempt", config, "defaultRecordPreempt")) {
		LOG(LOG_LV_ERR, "failed in get record preempt (group %s)", name);
		goto fail;
	}
	for (i = 0; i < sizeof(group_copy_params)/sizeof(group_copy_params[0]); i++) {
		snprintf(p, sizeof(p),  "%s.%s", name, group_copy_params[i].path);
		switch (group_copy_params[i].bson_type) {
		case BSON_STRING:
			if (bson_helper_itr_get_string(itr, &s, p, config, group_copy_params[i].default_path)) {
				LOG(LOG_LV_ERR, "failed in get %s (group %s)", group_copy_params[i].path, name);
				goto fail;
			}
			bson_append_string(status, group_copy_params[i].path, s);
			break;
		case BSON_BOOL:
			if (bson_helper_itr_get_bool(itr, &b, p, config, group_copy_params[i].default_path)) {
				LOG(LOG_LV_ERR, "failed in get %s (group %s)", group_copy_params[i].path, name);
				goto fail;
			}
			bson_append_bool(status, group_copy_params[i].path, b);
			break;
		case BSON_LONG:
			if (bson_helper_itr_get_long(itr, &l, p, config, group_copy_params[i].default_path)) {
				LOG(LOG_LV_ERR, "failed in get %s (group %s)", group_copy_params[i].path, name);
				goto fail;
			}
			bson_append_long(status, group_copy_params[i].path, l);
			break;
		default:
			/* NOTREACHED */
			ABORT("unexpected bson type");
		}
	}
	if (bhash_create(&address, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create address hash (group %s)", name);
		goto fail;
	}
	if (bhash_create(&hostname, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create hostname hash (group %s)", name);
		goto fail;
	}
	record_foreach_cb_arg.group_foreach_cb_arg = group_foreach_cb_arg;
	record_foreach_cb_arg.address = address;
	record_foreach_cb_arg.hostname = hostname;
	record_foreach_cb_arg.preempt = preempt;
	snprintf(p, sizeof(p),  "%s.%s", name, "records");
	if (bson_helper_itr_foreach(itr, p, watcher_record_foreach_cb, &record_foreach_cb_arg)) {
		LOG(LOG_LV_ERR, "failed in foreach of records (group %s)", name);
		goto fail;
	}
	/* XXXX group preempt */
	if (bhash_get_bhash_data(address, &bhash_data, &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of address hash (group %s)", name);
		goto fail;
	}
	if (bson_append_binary(status, "addresses", BSON_BIN_BINARY, bhash_data, bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of  address hash to new status (group %s)", name);
		goto fail;
	}
	if (bhash_get_bhash_data(hostname, &bhash_data, &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of hostname hash (group %s)", name);
		goto fail;
	}
	if (bson_append_binary(status, "hostnames", BSON_BIN_BINARY, bhash_data, bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of hostname hash to new status (group %s)", name);
		goto fail;
	}
	if (bhash_get_entry_count(address, &record_member_count)) {
		LOG(LOG_LV_ERR, "failed in get count of record member (group %s)", name);
		goto fail;
	}
	if (bson_append_long(status, "recordMembersCount", (int64_t)record_member_count)) {
		LOG(LOG_LV_ERR, "failed in append count of record member (group %s)", name);
		goto fail;
	}
	if (bhash_destroy(address)) {
		LOG(LOG_LV_ERR, "failed in destroy address hash (group %s)", name);
		goto fail;
	}
	if (bhash_destroy(hostname)) {
		LOG(LOG_LV_ERR, "failed in destroy hostname hash (group %s)", name);
		goto fail;
	}
        if (bson_append_finish_object(status) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in group entry object (group %s)", name);
                goto fail;
        }

	return BSON_HELPER_FOREACH_SUCCESS;

fail:
	if (address) {
		bhash_destroy(address);
	}
	if (hostname) {
		bhash_destroy(hostname);
	}
	if (group_object_start) {
		bson_append_finish_object(status);
	}

	return BSON_HELPER_FOREACH_ERROR;
}

static int
watcher_status_make(
    bson *status,
    size_t max_size,
    config_manager_t *config_manager,
    bhash_t *domain_map,
    bhash_t *remote_address_map,
    bhash_t *health_check) 
{
	int i;
	bson *config;
	char *bhash_data;
	size_t bhash_data_size;
	group_foreach_cb_arg_t group_foreach_cb_arg;
	int group_object_start;
	const char *default_record_status;
	

	if (status == NULL ||
	    config_manager == NULL ||
            domain_map == NULL ||
	    remote_address_map == NULL ||
	    health_check == NULL) {
		errno = EINVAL;
		return 1;
	}
	bson_init(status);
	if (config_manager_get_config(config_manager, &config)) {
		LOG(LOG_LV_ERR, "failed in get config");
		goto fail;
	}
	for (i = 0; i < sizeof(root_copy_params)/sizeof(root_copy_params[0]); i++) {
		switch (root_copy_params[i].bson_type) {
		case BSON_STRING:
			if (bson_helper_bson_copy_string(
			    status,
			    config,
			    root_copy_params[i].path,
			    NULL) != BSON_OK) {
				LOG(LOG_LV_ERR,
				    "failed in copy %s to new status from config",
				    root_copy_params[i].path);
				goto fail;
			}
			break;
		case BSON_BOOL:
			if (bson_helper_bson_copy_bool(
			    status,
			    config,
			    root_copy_params[i].path,
			    NULL) != BSON_OK) {
				LOG(LOG_LV_ERR,
				    "failed in copy %s to new status from config",
				    root_copy_params[i].path);
				goto fail;
			}
			break;
		case BSON_LONG:
			if (bson_helper_bson_copy_long(
			    status,
			    config,
			    root_copy_params[i].path,
			    NULL) != BSON_OK) {
				LOG(LOG_LV_ERR,
				    "failed in copy %s to new status from config",
				    root_copy_params[i].path);
				goto fail;
			}
			break;
		default:
			/* NOTREACHED */
			ABORT("unexpected bson type");
		}
	}
	if (bhash_get_bhash_data(
	    domain_map,
	    &bhash_data,
	    &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of domain map");
		goto fail;
	}
	if (bson_append_binary(
	    status,
	    "domainMap",
	    BSON_BIN_BINARY,
	    bhash_data,
	    bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of domain map to new status");
		goto fail;
	}
	if (bhash_get_bhash_data(
	    remote_address_map,
	    &bhash_data,
	    &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of remote address map");
		goto fail;
	}
	if (bson_append_binary(
	    status,
	    "remoteAddressMap",
	    BSON_BIN_BINARY,
	    bhash_data,
	    bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of remote address map to new status");
		goto fail;
	}
	if (bson_helper_bson_get_string(
	    config,
	    &default_record_status,
	    "defaultRecordStatus",
	    NULL)) {
		LOG(LOG_LV_ERR, "failed in get default record status");
		goto fail;
	}
	group_foreach_cb_arg.status = status;
	group_foreach_cb_arg.config = config;
	group_foreach_cb_arg.health_check = health_check;
	group_foreach_cb_arg.default_record_status = default_record_status;
	if (bson_append_start_object(status, "groups") != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in start group object");
		goto fail;
	}
	group_object_start = 1;
	if (bson_helper_bson_foreach(
	    config,
	    "groups",
	    watcher_group_foreach_cb,
	    &group_foreach_cb_arg)) {
		LOG(LOG_LV_ERR, "failed in foreach of groups");
		goto fail;
	}
	if (bson_append_finish_object(status) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in finish group object");
		goto fail;
	}
        if (bson_finish(status) != BSON_OK) {
		goto fail;
	}

	return 0;

fail:
	if (group_object_start) {
		bson_append_finish_object(status);
	}
	bson_destroy(status);

	return 1;
}

static void
watcher_status_clean(
     bson *status)
{
	ASSERT(status != NULL);
	bson_destroy(status);
}

static int
watcher_update(
    watcher_t *watcher)
{
	int mkstatus = 0;
	int oshbuf = 0;
	int64_t max_shared_buffer_size;
	bson status;
	const char *data;
	size_t data_size;

	ASSERT(watcher != NULL);
	if (config_manager_get_long(
	    watcher->config_manager,
	    &max_shared_buffer_size,
	    "maxSharedBufferSize",
	    NULL)) {
		LOG(LOG_LV_ERR, "failed in get max shared bufffer size");
		goto fail;
	}
	ASSERT(watcher != NULL);
	if (watcher_status_make(
	    &status,
	    max_shared_buffer_size,
	    watcher->config_manager,
	    watcher->domain_map.elements,
	    watcher->remote_address_map.elements,
	    watcher->health_check.elements)) {
		LOG(LOG_LV_ERR, "failed in update status");
		goto fail;
	}
        mkstatus = 1;
	data = bson_data(&status);
	data_size = bson_size(&status);
	if (data_size > max_shared_buffer_size) {
		LOG(LOG_LV_ERR, "actual data size is too large than max shared buffer size (max = %d, size = %d)", (int)max_shared_buffer_size, data_size);
		goto fail;
	}
        if (shared_buffer_wopen(watcher->shared_buffer, DAEMON_BUFFER_FILE_PATH,  data_size)) {
		LOG(LOG_LV_ERR, "failed in open shared buffer file (%s)", DAEMON_BUFFER_FILE_PATH);
                goto fail;
        }
	oshbuf = 1;
	if (shared_buffer_write(watcher->shared_buffer, data, data_size)) {
		LOG(LOG_LV_ERR, "failed in write shared buffer (%s)", DAEMON_BUFFER_FILE_PATH);
	}
        if (shared_buffer_close(watcher->shared_buffer)) {
		LOG(LOG_LV_ERR, "failed in close shared buffer file (%s)", DAEMON_BUFFER_FILE_PATH);
        }
	watcher_status_clean(&status);

	return 0;

fail:
	if (oshbuf) {
		shared_buffer_close(watcher->shared_buffer);
	}
	if (mkstatus) {
		watcher_status_clean(&status);
	}

	return 1;
}

static int
watcher_set_polling_common(
    watcher_t *watcher,
    watcher_target_type_t target_type)
{
	watcher_target_t *target = NULL;
        const char *default_path = "defaultPollingInterval";
        const char *path = NULL;
	int64_t interval;

	switch (target_type) {
        case TARGET_TYPE_DOMAIN_MAP:
		target = &watcher->domain_map;
		path = "domainMap.pollingInterval";
		break;
        case TARGET_TYPE_REMOTE_ADDRESS_MAP:
		target = &watcher->remote_address_map;
		path = "remoteAddressMap.pollingInterval";
		break;
        case TARGET_TYPE_HEALTH_CHECK:
		target = &watcher->health_check;
		path = "healthCheck.pollingInterval";
		break;
	default:
		ABORT("unknown target type");
		/* NOTREACHED */
	}
	if (config_manager_get_long(watcher->config_manager, &interval, path, default_path)) {
		LOG(LOG_LV_ERR, "failed in get polling interval (type = %d)", target_type);
		return 1;
	}
	target->polling_interval.tv_sec = (long)interval;
	evtimer_set(&target->event, watcher_polling_common, target);
	event_priority_set(&target->event, DEFAULT_EVENT_PRIORITY + 10);
	event_base_set(watcher->event_base, &target->event);
	evtimer_add(&target->event,& target->polling_interval);

	return 0;
}

static void
watcher_health_check_element_compare(
    void *replace_cb_arg,
    const char *key,
    size_t key_size,
    char *old_value,
    size_t old_value_size,
    char *new_value,
    size_t new_value_size)
{
	watcher_health_check_element_t *old_element = (watcher_health_check_element_t *)old_value;
	watcher_health_check_element_t *new_element = (watcher_health_check_element_t *)new_value;

        // take over old valid status in case down.
        // if preempt flag is enable, valid flag is true in shared date creating 
        if (old_element->valid == 0) {
		new_element->valid = 0;
	}
	if (old_element->current_status == 0 && new_element->current_status == 0) {
		new_element->latest_status_change = STATUS_CHANGE_KEEP_DOWN;
	} else if (old_element->current_status == 0 && new_element->current_status == 1) {
		LOG(LOG_LV_INFO, "%s status change down to up", key);
		new_element->latest_status_change = STATUS_CHANGE_DOWN_TO_UP;
	} else if (old_element->current_status == 1 && new_element->current_status == 0) {
		LOG(LOG_LV_INFO, "%s status change up to down", key);
		new_element->latest_status_change = STATUS_CHANGE_UP_TO_DOWN;
	} else if (old_element->current_status == 1 && new_element->current_status == 1) {
		new_element->latest_status_change = STATUS_CHANGE_KEEP_UP;
	}
}

static int
watcher_polling_common_add_element(
    watcher_target_type_t target_type,
    char *key,
    char *value,
    bhash_t *elements)
{
	watcher_health_check_element_t health_check_element;
	v4v6_addr_mask_t addr_mask;

	switch (target_type) {
        case TARGET_TYPE_DOMAIN_MAP:
		if (bhash_replace(
		    elements,
		    key,
		    strlen(key) + 1,
		    value,
		    strlen(value) + 1,
                    NULL,
		    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry (type = %d)", key, target_type);
			return 1;
		}
		break;
        case TARGET_TYPE_REMOTE_ADDRESS_MAP:
		if (addrstr_to_addrmask_b(&addr_mask, key)) {
			LOG(LOG_LV_INFO, "failed in convert string to address and mask %s entry (type = %d)", key, target_type);
			return 1;
		}
		if (bhash_replace(
		    elements,
		    (const char *)&addr_mask,
		    sizeof(v4v6_addr_mask_t),
		    value,
		    strlen(value) + 1,
                    NULL,
		    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry (type = %d)", key, target_type);
			return 1;
		}
		break;
        case TARGET_TYPE_HEALTH_CHECK:
		memset(&health_check_element, 0, sizeof(health_check_element));
		if (strcasecmp(value, "up") == 0) {
			health_check_element.current_status = 1;
			// mayby overwrite valid in compare 
			health_check_element.valid = 1;
		} else {
			health_check_element.current_status = 0;
			health_check_element.valid = 0;
		}
		if (bhash_replace(
		    elements,
		    key,
		    strlen(key) + 1,
		    (char *)&health_check_element,
		    sizeof(health_check_element),
		    watcher_health_check_element_compare,
                    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry of health check (type = %d)", key, target_type);
			return 1;	
		}
		break;
	default:
		ABORT("unknown target type");
		/* NOTREACHED */
	}

	return 0;
}

static void
watcher_polling_common_response(
    int fd,
    short ev,
    void *arg,
    exec_flag_t *exec_flag)
{
	watcher_target_t *target = arg;
	watcher_t *watcher;
	ssize_t read_len;
	char tmp_buffer[DEFAULT_IO_BUFFER_SIZE];
	size_t remain_len;
	char *line_start, *line_end;
	struct kv_split kv;
	int update_value = 0;

	ASSERT(target != NULL);
	ASSERT(target->backptr != NULL);
	watcher = target->backptr;
	switch (target->type) {
        case TARGET_TYPE_DOMAIN_MAP:
                update_value = 0x01;
		break;
        case TARGET_TYPE_REMOTE_ADDRESS_MAP:
                update_value = 0x02;
		break;
        case TARGET_TYPE_HEALTH_CHECK:
                update_value = 0x04;
		break;
	default:
		ABORT("unknown target type");
		/* NOTREACHED */
	}
	read_len = read(
	    fd,
	    &tmp_buffer[target->remain_buffer_len],
	    sizeof(tmp_buffer) - target->remain_buffer_len - 1);
	if (read_len <= 0) {
		if (read_len < 0) {
			LOG(LOG_LV_INFO, "failed in read (type = %d)", target->type);
			return;
		} else {
			memcpy(tmp_buffer,
			     target->remain_buffer,
			     target->remain_buffer_len);
			tmp_buffer[target->remain_buffer_len] = '\0';
			if (tmp_buffer[0] != '\0') {
				string_kv_split_b(&kv, tmp_buffer, " \t" );
				if (watcher_polling_common_add_element(
				    target->type,
				    kv.key,
				    kv.value,
				    target->elements)) {
					LOG(LOG_LV_INFO, "failed in add element (type = %d)", target->type);
				}
			}
		}
		target->remain_buffer_len = 0;
		*exec_flag = EXEC_FL_FINISH;
		watcher->updated |= update_value;
	} else {
		memcpy(tmp_buffer,
		     target->remain_buffer,
		     target->remain_buffer_len);
		tmp_buffer[read_len + target->remain_buffer_len] = '\0';
		line_start = tmp_buffer;
		while (1) {
			line_end = strchr(line_start, '\n');
			if (line_end == NULL) {
				break;
			}
			*line_end = '\0';
			string_kv_split_b(&kv, line_start, " \t" );
			if (watcher_polling_common_add_element(
			    target->type,
			    kv.key,
			    kv.value,
			    target->elements)) {
				LOG(LOG_LV_INFO, "failed in add element (type = %d)", target->type);
			}
			line_start = line_end + 1;
		}
		remain_len = (read_len + target->remain_buffer_len) - (line_start - tmp_buffer);
		memcpy(target->remain_buffer, line_start, remain_len);
		target->remain_buffer_len = remain_len;
	}
}

static void 
watcher_polling_common(
    int fd,
    short ev,
    void *arg)
{
	watcher_target_t *target = arg;
	watcher_t *watcher;
	const char *path;
	const char *execute_script;

	ASSERT(target != NULL);
	ASSERT(target->backptr != NULL);
	watcher = target->backptr;
	switch (target->type) {
        case TARGET_TYPE_DOMAIN_MAP:
		path = "domainMap.executeScript";
		break;
        case TARGET_TYPE_REMOTE_ADDRESS_MAP:
		path = "remoteAddressMap.executeScript";
		break;
        case TARGET_TYPE_HEALTH_CHECK:
		path = "healthCheck.executeScript";
		break;
	default:
		ABORT("unknown target type");
		/* NOTREACHED */
	}
	if (config_manager_get_string(watcher->config_manager, &execute_script, path, NULL)) {
		LOG(LOG_LV_INFO, "failed in get script (type = %d)", target->type);
		goto last;
	}
	if (executor_exec(
	    watcher->executor,
	    execute_script,
	    watcher_polling_common_response,
	    target)) {
		LOG(LOG_LV_INFO, "failed in execute script (type = %d)", target->type);
	}
last:
	watcher_set_polling_common(watcher, target->type);
}

static int
watcher_set_polling_update_check(
    watcher_t *watcher)
{
	watcher->update_check_interval.tv_sec = 1;
	evtimer_set(&watcher->update_check_event, watcher_polling_update_check, watcher);
	event_priority_set(&watcher->update_check_event, DEFAULT_EVENT_PRIORITY + 20);
	event_base_set(watcher->event_base, &watcher->update_check_event);
	evtimer_add(&watcher->update_check_event, &watcher->update_check_interval);

	return 0;
}

static void
watcher_polling_update_check(
    int fd,
    short ev,
    void *arg)
{
	watcher_t *watcher = arg;

	if (watcher->updated != 0) {
		watcher_update(watcher);
		watcher->updated = 0;
		// When updated variable is not zero, there is a possibility
		// that a certain process is completed. 
		// The exited processes which were not able to be collected
		// in sigchild event are collected periodically. 
		executor_waitpid(watcher->executor);
	}
	watcher_set_polling_update_check(watcher);
}

int
watcher_create(
    watcher_t **watcher,
    struct event_base *event_base,
    config_manager_t *config_manager)
{
	watcher_t *new = NULL;
	shared_buffer_t *new_shared_buffer = NULL;
	executor_t *new_executor = NULL;
	bhash_t *new_domain_map = NULL;
	bhash_t *new_remote_address_map = NULL;
	bhash_t *new_health_check = NULL;
	if (watcher == NULL ||
	    event_base == NULL ||
	    config_manager == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(watcher_t));
	if (new == NULL) {
		goto fail;
	}
        if (shared_buffer_create(&new_shared_buffer)) {
                goto fail;
        }
	new->shared_buffer = new_shared_buffer;
        if (executor_create(&new_executor, event_base)) {
                goto fail;
        }
        if (bhash_create(&new_domain_map, DEFAULT_HASH_SIZE, NULL, NULL)) {
                goto fail;
        }
        if (bhash_create(&new_remote_address_map, DEFAULT_HASH_SIZE, NULL, NULL)) {
                goto fail;
        }
        if (bhash_create(&new_health_check, DEFAULT_HASH_SIZE, NULL, NULL)) {
                goto fail;
        }
	new->domain_map.type = TARGET_TYPE_DOMAIN_MAP;
	new->domain_map.elements = new_domain_map;
	new->domain_map.backptr = new;
	new->remote_address_map.type = TARGET_TYPE_REMOTE_ADDRESS_MAP;
	new->remote_address_map.elements = new_remote_address_map;
	new->remote_address_map.backptr = new;
	new->health_check.type = TARGET_TYPE_HEALTH_CHECK;
	new->health_check.elements = new_health_check;
	new->health_check.backptr = new;
	new->executor = new_executor;
	new->event_base = event_base;
	new->config_manager = config_manager;
	*watcher = new;

	return 0;

fail:
        if (new_domain_map) {
		bhash_destroy(new_domain_map);
        }
        if (new_remote_address_map) {
		bhash_destroy(new_remote_address_map);
        }
        if (new_health_check) {
		bhash_destroy(new_health_check);
        }
	if (new_executor) {
		executor_destroy(new_executor);
	}
	if (new_shared_buffer) {
		shared_buffer_destroy(new_shared_buffer);
	}
	free(new);

	return 1;
}

int
watcher_destroy(
    watcher_t *watcher)
{
	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
        if (watcher->domain_map.elements) {
		bhash_destroy(watcher->domain_map.elements);
        }
        if (watcher->remote_address_map.elements) {
		bhash_destroy(watcher->remote_address_map.elements);
        }
        if (watcher->health_check.elements) {
		bhash_destroy(watcher->health_check.elements);
        }
	if (watcher->executor) {
		executor_waitpid(watcher->executor);
		executor_destroy(watcher->executor);
	}
	if (watcher->shared_buffer) {
		shared_buffer_destroy(watcher->shared_buffer);
	}
	free(watcher);

	return 0;
}

int
watcher_polling_start(
    watcher_t *watcher)
{
	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	watcher_set_polling_common(watcher, TARGET_TYPE_DOMAIN_MAP);
	watcher_set_polling_common(watcher, TARGET_TYPE_REMOTE_ADDRESS_MAP);
	watcher_set_polling_common(watcher, TARGET_TYPE_HEALTH_CHECK);
	watcher_set_polling_update_check(watcher);

	return 0;
}

int
watcher_polling_stop(
    watcher_t *watcher)
{
	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	evtimer_del(&watcher->domain_map.event);
	evtimer_del(&watcher->remote_address_map.event);
	evtimer_del(&watcher->health_check.event);
	evtimer_del(&watcher->update_check_event);

	return 0;
}

int
watcher_sigchild(
    watcher_t *watcher)
{
	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	executor_waitpid(watcher->executor);

	return 0;
}

