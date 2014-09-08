#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
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
#include "common_struct.h"
#include "logger.h"

#ifndef DEFAULT_IO_BUFFER_SIZE
#define DEFAULT_IO_BUFFER_SIZE 2048
#endif

#define MAX_RECORD_BUFFER (INET6_ADDRSTRLEN + NI_MAXHOST + sizeof(record_buffer_t) + 8)
#define MAX_ADDRESS_HOSTNAME_BUFFER (INET6_ADDRSTRLEN + NI_MAXHOST + 1024)
#define ALIGN_SIZE(size) ((size) + 8 - ((size) & 7))

typedef enum watcher_target_type watcher_target_type_t;
typedef enum watcher_status_change watcher_status_change_t;
typedef struct watcher_status_element watcher_status_element_t;
typedef struct watcher_target watcher_target_t;
typedef struct group_foreach_cb_arg group_foreach_cb_arg_t;
typedef struct forward_record_foreach_cb_arg forward_record_foreach_cb_arg_t;
typedef struct reverse_record_foreach_cb_arg reverse_record_foreach_cb_arg_t;
typedef struct root_copy_param root_copy_param_t;
typedef struct sub_copy_param sub_copy_param_t;
typedef struct watcher_status_foreach_cb_arg watcher_status_foreach_cb_arg_t;

enum watcher_target_type {
	TARGET_TYPE_DOMAIN_MAP = 1,
	TARGET_TYPE_REMOTE_ADDRESS_MAP,
	TARGET_TYPE_ADDRESS_HEALTH_CHECK,
	TARGET_TYPE_HOSTNAME_HEALTH_CHECK,
	TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK
};

struct watcher_status_element {
        int current_status;
        int previous_status;
        int preempt_status;
};

struct watcher_target {
        watcher_target_type_t type;
	struct event event;
	struct timeval polling_interval;
	char remain_buffer[DEFAULT_IO_BUFFER_SIZE];
	size_t remain_buffer_len;
        bhash_t *elements;
        bhash_t *tmp_elements;
	int reading;
        watcher_t *backptr;
};

struct watcher {
        watcher_target_t domain_map;
        watcher_target_t remote_address_map;
        watcher_target_t address_health_check;
        watcher_target_t hostname_health_check;
        watcher_target_t address_hostname_health_check;
        bhash_t *groups;
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
        bhash_t *address_health_check;
        bhash_t *hostname_health_check;
        bhash_t *address_hostname_health_check;
	bhash_t *new_groups;
	bhash_t *old_groups;
	int group_preempt;
	const char *default_record_status;
	int active_group_members_count;
};

struct forward_record_foreach_cb_arg {
	group_foreach_cb_arg_t *group_foreach_cb_arg;
	bhash_t *ipv4hostname;
	bhash_t *ipv6hostname;
	int preempt;
};

struct reverse_record_foreach_cb_arg {
	group_foreach_cb_arg_t *group_foreach_cb_arg;
	bhash_t *ipv4address;
	bhash_t *ipv6address;
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

struct watcher_status_foreach_cb_arg {
	void (*foreach_cb)(void *foreach_cb_arg, const char *name);
	void *foreach_cb_arg;
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
	{ BSON_LONG, "maxForwardRecords", "defaultMaxForwardRecords" },
	{ BSON_LONG, "maxReverseRecords", "defaultMaxReverseRecords" },
	{ BSON_LONG, "recordSelectAlgorithmValue", "defaultRecordSelectAlgorithmValue" },
	{ BSON_BOOL, "recordPreempt", "defaultRcordPreempt" },
	{ BSON_LONG, "groupPriority", "defaultGroupPriority" }
};

static int watcher_forward_record_foreach_cb(
    void *record_foreach_cb_arg,
    const char *path,
    bson_iterator *itr);
static int watcher_reverse_record_foreach_cb(
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
    bhash_t *address_health_check,
    bhash_t *hostname_health_check,
    bhash_t *address_hostname_health_check,
    bhash_t *new_groups,
    bhash_t *old_groups);
static void watcher_status_clean(bson *status);
static int watcher_update(watcher_t *watcher);
static int watcher_polling_common_add_element(
    watcher_target_type_t target_type,
    char *key,
    char *value,
    bhash_t *new_elements,
    bhash_t *old_elements);
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
static void watcher_status_foreach_cb(
    void *foreach_cb_arg,
    int idx,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size);

static int
watcher_forward_record_foreach_cb(
    void *forward_record_foreach_cb_arg,
    const char *path,
    bson_iterator *itr)
{
	forward_record_foreach_cb_arg_t *arg = forward_record_foreach_cb_arg;
	bson *config;
	bhash_t *address_health_check, *hostname_health_check, *address_hostname_health_check;
	bhash_t *hostname;
	const char *default_record_status;
	char p[MAX_BSON_PATH_LEN];
	char entry_buffer[MAX_RECORD_BUFFER];
	record_buffer_t *entry;
	const char *idx, *addr, *host;
	char addr_host[MAX_ADDRESS_HOSTNAME_BUFFER];
	size_t addr_size, host_size, addr_host_size;
	watcher_status_element_t *address_health_check_element = NULL;
	watcher_status_element_t *hostname_health_check_element = NULL;
	watcher_status_element_t *address_hostname_health_check_element = NULL;
	v4v6_addr_mask_t *addr_mask;
	size_t addr_mask_size;
	int force_down = 0;
	int address_current_status = 1, address_preempt_status = 1;
	int hostname_current_status = 1, hostname_preempt_status = 1;
	int address_hostname_current_status = 1, address_hostname_preempt_status = 1;
	/*
         * not return BSON_HELPER_FOREACH_ERROR
         * then, skip record entry
         */ 
	int error = BSON_HELPER_FOREACH_SUCCESS;
	
	ASSERT(arg != NULL);
	ASSERT(arg->group_foreach_cb_arg != NULL);
	ASSERT(arg->group_foreach_cb_arg->config != NULL);
	ASSERT(arg->group_foreach_cb_arg->status != NULL);
	ASSERT(arg->group_foreach_cb_arg->default_record_status != NULL);
	ASSERT(arg->ipv4hostname != NULL);
	ASSERT(arg->ipv6hostname != NULL);
	config = arg->group_foreach_cb_arg->config;
	address_health_check = arg->group_foreach_cb_arg->address_health_check;
	hostname_health_check = arg->group_foreach_cb_arg->hostname_health_check;
	address_hostname_health_check = arg->group_foreach_cb_arg->address_hostname_health_check;
	default_record_status = arg->group_foreach_cb_arg->default_record_status;
	entry = (record_buffer_t *)&entry_buffer[0];
	idx = bson_iterator_key(itr);

	snprintf(p, sizeof(p),  "%s.forceDown", idx);
	if (bson_helper_itr_get_bool(itr, &force_down, p, NULL, NULL )) {
		// pass
	}
	if (force_down) {
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.address", idx);
	if (bson_helper_itr_get_string(itr, &addr, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get address (index = %s)", idx);
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.addressAndMask", idx);
	if (bson_helper_itr_get_binary(itr, (char const **)&addr_mask, &addr_mask_size, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get address and mask (index = %s)", idx);
		goto last;
	}
	switch (addr_mask->addr.family) {
	case AF_INET:
		hostname = arg->ipv4hostname; 
		break;
	case AF_INET6:
		hostname = arg->ipv6hostname;
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected address family");
		goto last;
	}
	addr_size = strlen(addr) + 1;
	snprintf(p, sizeof(p),  "%s.hostname", idx);
	if (bson_helper_itr_get_string(itr, &host, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get hostname (index = %s)", idx);
		goto last;
	}
	host_size = strlen(host) + 1;
	if (address_health_check) {
		LOG(LOG_LV_DEBUG, "address = %s", addr);
		if (bhash_get(address_health_check, (char **)&address_health_check_element, NULL, addr, addr_size)) {
			LOG(LOG_LV_ERR, "failed in get address health (index = %s)", idx);
			goto last;
		}
	}
	if (hostname_health_check) {
		LOG(LOG_LV_DEBUG, "hostname = %s", host);
		if (bhash_get(hostname_health_check, (char **)&hostname_health_check_element, NULL, host, host_size)) {
			LOG(LOG_LV_ERR, "failed in get hostname health (index = %s)", idx);
			goto last;
		}
	}
	if (address_hostname_health_check) {
		addr_host_size = snprintf(addr_host, sizeof(addr_host), "%s@%s", addr, host);
		LOG(LOG_LV_DEBUG, "address and hostname = %s", addr_host);
		if (bhash_get(address_hostname_health_check, (char **)&address_hostname_health_check_element, NULL, addr_host, addr_host_size + 1)) {
			LOG(LOG_LV_ERR, "failed in get address and hostname health (index = %s)", idx);
			goto last;
		}
	}
	// 現在のステータスがupの場合preemptが有効であれば、preemptのstatusもupにする 
	// 本来はpolling結果のとこでやりたいが、設定を取得しにくいのでここでやっている
	if (address_health_check_element) {
		if (arg->preempt && address_health_check_element->current_status == 1) {
			address_health_check_element->preempt_status = 1;
		}
		address_current_status = address_health_check_element->current_status;
		address_preempt_status = address_health_check_element->preempt_status;
	}
	if (hostname_health_check_element) {
		if (arg->preempt && hostname_health_check_element->current_status == 1) {
			hostname_health_check_element->preempt_status = 1;
		}
		hostname_current_status = hostname_health_check_element->current_status;
		hostname_preempt_status = hostname_health_check_element->preempt_status;
	}
	if (address_hostname_health_check_element) {
		if (arg->preempt && address_hostname_health_check_element->current_status == 1) {
			address_hostname_health_check_element->preempt_status = 1;
		}
		address_hostname_current_status = address_hostname_health_check_element->current_status;
		address_hostname_preempt_status = address_hostname_health_check_element->preempt_status;
	}
	if (address_health_check_element == NULL &&
            hostname_health_check_element == NULL &&
            address_hostname_health_check_element == NULL) {
		if (strcasecmp(default_record_status, "up") != 0) {
			goto last;
		}
	} else if (!(address_current_status & address_preempt_status & 
	      hostname_current_status & hostname_preempt_status &
	      address_hostname_current_status & address_hostname_preempt_status)) {
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.ttl", idx);
	if (bson_helper_itr_get_long(itr, &entry->ttl, p, config, "defaultTtl")) {
		LOG(LOG_LV_ERR, "failed in get ttl (index = %s)", idx);
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.recordPriority", idx);
	if (bson_helper_itr_get_long(itr, &entry->record_priority, p, config, "defaultRecordPriority")) {
		LOG(LOG_LV_ERR, "failed in get record priority (index = %s)", idx);
		goto last;
	}
	entry->value_size = addr_size;
	memcpy(((char *)entry) + offsetof(record_buffer_t, value), addr, addr_size);
	if (bhash_append(hostname,
	    host,
	    host_size,
	    (char *)entry,
	    sizeof(record_buffer_t) + entry->value_size)) {
		LOG(LOG_LV_ERR, "failed in append hostname (index %s)", idx);
		goto last;
	}

	return BSON_HELPER_FOREACH_SUCCESS;
last:
	return error;
}

static int
watcher_reverse_record_foreach_cb(
    void *reverse_record_foreach_cb_arg,
    const char *path,
    bson_iterator *itr)
{
	reverse_record_foreach_cb_arg_t *arg = reverse_record_foreach_cb_arg;
	bson *config;
	bhash_t *address_health_check, *hostname_health_check, *address_hostname_health_check;
	bhash_t *address;
	const char *default_record_status;
	char p[MAX_BSON_PATH_LEN];
	char entry_buffer[MAX_RECORD_BUFFER];
	record_buffer_t *entry;
	const char *idx, *addr, *host;
	char addr_host[MAX_ADDRESS_HOSTNAME_BUFFER];
	size_t addr_size, host_size, addr_host_size;
	watcher_status_element_t *address_health_check_element = NULL;
	watcher_status_element_t *hostname_health_check_element = NULL;
	watcher_status_element_t *address_hostname_health_check_element = NULL;
	v4v6_addr_mask_t *addr_mask;
	size_t addr_mask_size;
	int force_down = 0;
	int address_current_status = 1, address_preempt_status = 1;
	int hostname_current_status = 1, hostname_preempt_status = 1;
	int address_hostname_current_status = 1, address_hostname_preempt_status = 1;
	/*
         * not return BSON_HELPER_FOREACH_ERROR
         * then, skip record entry
         */ 
	int error = BSON_HELPER_FOREACH_SUCCESS;
	
	ASSERT(arg != NULL);
	ASSERT(arg->group_foreach_cb_arg != NULL);
	ASSERT(arg->group_foreach_cb_arg->config != NULL);
	ASSERT(arg->group_foreach_cb_arg->status != NULL);
	ASSERT(arg->group_foreach_cb_arg->default_record_status != NULL);
	ASSERT(arg->ipv4address != NULL);
	ASSERT(arg->ipv6address != NULL);
	config = arg->group_foreach_cb_arg->config;
	address_health_check = arg->group_foreach_cb_arg->address_health_check;
	hostname_health_check = arg->group_foreach_cb_arg->hostname_health_check;
	address_hostname_health_check = arg->group_foreach_cb_arg->address_hostname_health_check;
	default_record_status = arg->group_foreach_cb_arg->default_record_status;
	entry = (record_buffer_t *)&entry_buffer[0];
	idx = bson_iterator_key(itr);

	// forceDownがtrueなら無視
	snprintf(p, sizeof(p),  "%s.forceDown", idx);
	if (bson_helper_itr_get_bool(itr, &force_down, p, NULL, NULL )) {
		// pass
	}
	if (force_down) {
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.address", idx);
	if (bson_helper_itr_get_string(itr, &addr, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get address (index = %s)", idx);
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.addressAndMask", idx);
	if (bson_helper_itr_get_binary(itr, (char const **)&addr_mask, &addr_mask_size, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get address and mask (index = %s)", idx);
		goto last;
	}
	switch (addr_mask->addr.family) {
	case AF_INET:
		address = arg->ipv4address;
		break;
	case AF_INET6:
		address = arg->ipv6address;
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected address family");
		goto last;
	}
	addr_size = strlen(addr) + 1;
	snprintf(p, sizeof(p),  "%s.hostname", idx);
	if (bson_helper_itr_get_string(itr, &host, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get hostname (index = %s)", idx);
		goto last;
	}
	host_size = strlen(host) + 1;
	if (address_health_check) {
		LOG(LOG_LV_DEBUG, "address = %s", addr);
		if (bhash_get(address_health_check, (char **)&address_health_check_element, NULL, addr, addr_size)) {
			LOG(LOG_LV_ERR, "failed in get health (index = %s)", idx);
			goto last;
		}
	}
	if (hostname_health_check) {
		LOG(LOG_LV_DEBUG, "hostname = %s", host);
		if (bhash_get(hostname_health_check, (char **)&hostname_health_check_element, NULL, host, host_size)) {
			LOG(LOG_LV_ERR, "failed in get health (index = %s)", idx);
			goto last;
		}
	}
	if (address_hostname_health_check) {
		addr_host_size = snprintf(addr_host, sizeof(addr_host), "%s@%s", addr, host);
		LOG(LOG_LV_DEBUG, "address and hostname = %s", addr_host);
		if (bhash_get(address_hostname_health_check, (char **)&address_hostname_health_check_element, NULL, addr_host, addr_host_size + 1)) {
			LOG(LOG_LV_ERR, "failed in get health (index = %s)", idx);
			goto last;
		}
	}
	// 現在のステータスがupの場合preemptが有効であれば、preemptのstatusもupにする 
	// 本来はpolling結果のとこでやりたいが、設定を取得しにくいのでここでやっている
	if (address_health_check_element) {
		if (arg->preempt && address_health_check_element->current_status == 1) {
			address_health_check_element->preempt_status = 1;
		}
		address_current_status = address_health_check_element->current_status;
		address_preempt_status = address_health_check_element->preempt_status;
	}
	if (hostname_health_check_element) {
		if (arg->preempt && hostname_health_check_element->current_status == 1) {
			hostname_health_check_element->preempt_status = 1;
		}
		hostname_current_status = hostname_health_check_element->current_status;
		hostname_preempt_status = hostname_health_check_element->preempt_status;
	}
	if (address_hostname_health_check_element) {
		if (arg->preempt && address_hostname_health_check_element->current_status == 1) {
			address_hostname_health_check_element->preempt_status = 1;
		}
		address_hostname_current_status = address_hostname_health_check_element->current_status;
		address_hostname_preempt_status = address_hostname_health_check_element->preempt_status;
	}
	if (address_health_check_element == NULL &&
            hostname_health_check_element == NULL &&
            address_hostname_health_check_element == NULL) {
		if (strcasecmp(default_record_status, "up") != 0) {
			goto last;
		}
	} else if (!(address_current_status & address_preempt_status & 
	      hostname_current_status & hostname_preempt_status &
	      address_hostname_current_status & address_hostname_preempt_status)) {
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.ttl", idx);
	if (bson_helper_itr_get_long(itr, &entry->ttl, p, config, "defaultTtl")) {
		LOG(LOG_LV_ERR, "failed in get ttl (index = %s)", idx);
		goto last;
	}
	snprintf(p, sizeof(p),  "%s.recordPriority", idx);
	if (bson_helper_itr_get_long(itr, &entry->record_priority, p, config, "defaultRecordPriority")) {
		LOG(LOG_LV_ERR, "failed in get record priority (index = %s)", idx);
		goto last;
	}
	entry->value_size = host_size;
	memcpy(((char *)entry) + offsetof(record_buffer_t, value), host, host_size);
	if (bhash_append(address,
	    (char *)addr_mask,
	    addr_mask_size,
	    (char *)entry,
	    sizeof(record_buffer_t) + entry->value_size)) {
		LOG(LOG_LV_ERR, "failed in append address (index = %s)", idx);
		goto last;
	}

	return BSON_HELPER_FOREACH_SUCCESS;
last:
	return error;
}

static int
watcher_group_foreach_cb(
    void *group_foreach_cb_arg,
    const char *path,
    bson_iterator *itr)
{
	int i;
	group_foreach_cb_arg_t *arg = group_foreach_cb_arg;
	forward_record_foreach_cb_arg_t forward_record_foreach_cb_arg;
	reverse_record_foreach_cb_arg_t reverse_record_foreach_cb_arg;
	bson *config;
	bson *status = NULL;
	const char *name;
	size_t name_size;
	int64_t l;
	int b, preempt;
	const char *s;
	char p[MAX_BSON_PATH_LEN];
	int group_object_start = 0;
	bhash_t *ipv4address = NULL, *ipv4hostname = NULL;
	bhash_t *ipv6address = NULL, *ipv6hostname = NULL;
	char *bhash_data;
	size_t bhash_data_size;
	int ipv4address_record_member_count = 0, ipv6address_record_member_count = 0;
	int ipv4hostname_record_member_count = 0, ipv6hostname_record_member_count = 0;
	watcher_status_element_t new_group_status, *old_group_status = NULL;
	int force_down = 0;
	int result = BSON_HELPER_FOREACH_ERROR;
	int active_records;

	ASSERT(arg != NULL);
	ASSERT(arg->config != NULL);
	ASSERT(arg->status != NULL);
	ASSERT(arg->default_record_status != NULL);
	config = arg->config;
	status = arg->status;
	name = bson_iterator_key(itr);

	// forceDownがtrueなら無視
	snprintf(p, sizeof(p),  "%s.%s", name, "forceDown");
	if (bson_helper_itr_get_bool(itr, &force_down, p, NULL, NULL)) {
		// pass
	}
	if (force_down) {
		result = BSON_HELPER_FOREACH_SUCCESS;
		goto last;
	}
	// preemptの設定は先に読む
	if (bson_helper_itr_get_bool(itr, &preempt, "recordPreempt", config, "defaultRecordPreempt")) {
		LOG(LOG_LV_ERR, "failed in get record preempt (group %s)", name);
		goto last;
	}
	// 一時的にbitmap領域を作成
	if (bhash_create(&ipv4address, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create address hash (group %s)", name);
		goto last;
	}
	if (bhash_create(&ipv4hostname, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create hostname hash (group %s)", name);
		goto last;
	}
	if (bhash_create(&ipv6address, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create address hash (group %s)", name);
		goto last;
	}
	if (bhash_create(&ipv6hostname, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create hostname hash (group %s)", name);
		goto last;
	}
	// コールバック引数を作る
	forward_record_foreach_cb_arg.group_foreach_cb_arg = arg;
	forward_record_foreach_cb_arg.ipv4hostname = ipv4hostname;
	forward_record_foreach_cb_arg.ipv6hostname = ipv6hostname;
	forward_record_foreach_cb_arg.preempt = preempt;
	reverse_record_foreach_cb_arg.group_foreach_cb_arg = arg;
	reverse_record_foreach_cb_arg.ipv4address = ipv4address;
	reverse_record_foreach_cb_arg.ipv6address = ipv6address;
	reverse_record_foreach_cb_arg.preempt = preempt;
	// コンフィグの正引きレコード情報を読み込む
	// この際health checkの値も考慮する
	snprintf(p, sizeof(p),  "%s.%s", name, "forwardRecords");
	if (bson_helper_itr_foreach(itr, p, watcher_forward_record_foreach_cb, &forward_record_foreach_cb_arg)) {
		// not found forward records
	}
	// コンフィグの逆引きレコード情報を読み込む
	snprintf(p, sizeof(p),  "%s.%s", name, "reverseRecords");
	if (bson_helper_itr_foreach(itr, p, watcher_reverse_record_foreach_cb, &reverse_record_foreach_cb_arg)) {
		// not found reverse records
	}
	// レコードカウントの取得
	if (bhash_get_entry_count(ipv4hostname, &ipv4hostname_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in get count of record member (group %s)", name);
		goto last;
	}
	if (bhash_get_entry_count(ipv6hostname, &ipv6hostname_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in get count of record member (group %s)", name);
		goto last;
	}
	if (bhash_get_entry_count(ipv4address, &ipv4address_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in get count of record member (group %s)", name);
		goto last;
	}
	if (bhash_get_entry_count(ipv6address, &ipv6address_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in get count of record member (group %s)", name);
		goto last;
	}
	name_size = strlen(name) + 1;
	// 古いgroupステータスを取得
	new_group_status.previous_status = 1;
	new_group_status.preempt_status = 1;
	if (arg->old_groups) {
		if (bhash_get(arg->old_groups, (char **)&old_group_status, NULL, name, name_size)) {
			// pass
		}
		// previous_statusとpreempt_status情報を新しいgroupステータスに継承
		if (old_group_status) {
			new_group_status.previous_status = old_group_status->current_status;
			new_group_status.preempt_status = old_group_status->preempt_status;
		}
	}
	// 何もrecordがない場合はdownとみなす
        active_records = ipv4hostname_record_member_count +
            ipv6hostname_record_member_count +
            ipv4address_record_member_count +
            ipv6address_record_member_count;
	LOG(LOG_LV_DEBUG, "active records = %d (group %s)", active_records, name);
	if (active_records == 0) {
		new_group_status.current_status = 0;
		new_group_status.preempt_status = 0;
	} else {
		// group_preemptが立っていて、現在のステータスがupであればpreempt_statusを戻す
		new_group_status.current_status = 1;
		if (arg->group_preempt) {
			new_group_status.preempt_status = 1;
		}
	}
	// ログ出力
	if (new_group_status.previous_status == 0 && new_group_status.current_status == 1) {
		// DOWN TO UP
		LOG(LOG_LV_INFO, "%s status change down to up (group)", name);
	} else if (new_group_status.previous_status == 1 && new_group_status.current_status == 0) {
		// UP TO DOWN
		LOG(LOG_LV_INFO, "%s status change up to down (group)", name);
	}
	// bhashに保存
	if (bhash_replace(
	    arg->new_groups,
	    name,
	    name_size,
	    (char *)&new_group_status,
	    sizeof(new_group_status),
            NULL,
	    NULL)) {
		LOG(LOG_LV_INFO, "failed in replace %s entry (groups)", name);
		goto last;
	}
	// groupのステータスがdownまたはpreempt_statusがdownであれば終了
	if (!(new_group_status.current_status & new_group_status.preempt_status)) {
		result = BSON_HELPER_FOREACH_SUCCESS;
		goto last;
	}
	// activeなグループのカウントを取っておく
	arg->active_group_members_count++;
	// bsonにデータを追加開始
        if (bson_append_start_object(status, name) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in start group entry object (group %s)", name);
                goto last;
        }
	group_object_start = 1;
	// bsonにconfigパラメータを追加
	for (i = 0; i < sizeof(group_copy_params)/sizeof(group_copy_params[0]); i++) {
		snprintf(p, sizeof(p),  "%s.%s", name, group_copy_params[i].path);
		switch (group_copy_params[i].bson_type) {
		case BSON_STRING:
			if (bson_helper_itr_get_string(itr, &s, p, config, group_copy_params[i].default_path)) {
				LOG(LOG_LV_ERR, "failed in get %s (group %s)", group_copy_params[i].path, name);
				goto last;
			}
			bson_append_string(status, group_copy_params[i].path, s);
			break;
		case BSON_BOOL:
			if (bson_helper_itr_get_bool(itr, &b, p, config, group_copy_params[i].default_path)) {
				LOG(LOG_LV_ERR, "failed in get %s (group %s)", group_copy_params[i].path, name);
				goto last;
			}
			bson_append_bool(status, group_copy_params[i].path, b);
			break;
		case BSON_LONG:
			if (bson_helper_itr_get_long(itr, &l, p, config, group_copy_params[i].default_path)) {
				LOG(LOG_LV_ERR, "failed in get %s (group %s)", group_copy_params[i].path, name);
				goto last;
			}
			bson_append_long(status, group_copy_params[i].path, l);
			break;
		default:
			/* NOTREACHED */
			ABORT("unexpected bson type");
			goto last;
		}
	}
	// ipv4正引き用のbitmapデータを取り出す
	if (bhash_get_bhash_data(ipv4hostname, &bhash_data, &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of hostname hash (group %s)", name);
		goto last;
	}
	// bsonに取り出したipv4正引き用のbitmapデータを保存する
	if (bson_append_binary(status, "ipv4Hostnames", BSON_BIN_BINARY, bhash_data, bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of hostname hash to new status (group %s)", name);
		goto last;
	}
	if (bson_append_long(status, "ipv4HostnameRecordMembersCount", (int64_t)ipv4hostname_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in append count of record member (group %s)", name);
		goto last;
	}
	// ipv6正引き用のbitmapデータを取り出す
	if (bhash_get_bhash_data(ipv6hostname, &bhash_data, &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of hostname hash (group %s)", name);
		goto last;
	}
	// bsonに取り出したipv6正引き用のbitmapデータを保存する
	if (bson_append_binary(status, "ipv6Hostnames", BSON_BIN_BINARY, bhash_data, bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of hostname hash to new status (group %s)", name);
		goto last;
	}
	if (bson_append_long(status, "ipv6HostnameRecordMembersCount", (int64_t)ipv6hostname_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in append count of record member (group %s)", name);
		goto last;
	}
        // ipv4の逆引き用のbitmapデータを取り出す
	if (bhash_get_bhash_data(ipv4address, &bhash_data, &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of address hash (group %s)", name);
		goto last;
	}
	// bsonに取り出したipv4逆引き用のbitmapデータを保存する
	if (bson_append_binary(status, "ipv4Addresses", BSON_BIN_BINARY, bhash_data, bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of  address hash to new status (group %s)", name);
		goto last;
	}
	if (bson_append_long(status, "ipv4AddressRecordMembersCount", (int64_t)ipv4address_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in append count of record member (group %s)", name);
		goto last;
	}
	// ipv6の逆引き用のbitmapデータを取り出す
	if (bhash_get_bhash_data(ipv6address, &bhash_data, &bhash_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of address hash (group %s)", name);
		goto last;
	}
	// bsonに取り出したipv6逆引き用のbitmapデータを保存する
	if (bson_append_binary(status, "ipv6Addresses", BSON_BIN_BINARY, bhash_data, bhash_data_size) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append data of  address hash to new status (group %s)", name);
		goto last;
	}
	if (bson_append_long(status, "ipv6AddressRecordMembersCount", (int64_t)ipv6address_record_member_count)) {
		LOG(LOG_LV_ERR, "failed in append count of record member (group %s)", name);
		goto last;
	}
	result = BSON_HELPER_FOREACH_SUCCESS;

last:
	if (ipv4address) {
		bhash_destroy(ipv4address);
	}
	if (ipv4hostname) {
		bhash_destroy(ipv4hostname);
	}
	if (ipv6address) {
		bhash_destroy(ipv6address);
	}
	if (ipv6hostname) {
		bhash_destroy(ipv6hostname);
	}
	if (group_object_start) {
		bson_append_finish_object(status);
	}

	return result;
}

static int
watcher_status_make(
    bson *status,
    size_t max_size,
    config_manager_t *config_manager,
    bhash_t *domain_map,
    bhash_t *remote_address_map,
    bhash_t *address_health_check,
    bhash_t *hostname_health_check,
    bhash_t *address_hostname_health_check,
    bhash_t *new_groups,
    bhash_t *old_groups) 
{
	int i;
	bson *config;
	char *bhash_data;
	size_t bhash_data_size;
	group_foreach_cb_arg_t group_foreach_cb_arg;
	int group_object_start;
	const char *default_record_status;
	int group_preempt;

	if (status == NULL ||
	    config_manager == NULL ||
	    new_groups == NULL) {
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
			goto fail;
		}
	}
	if (domain_map) {
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
	}
	if (remote_address_map) {
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
	}
	if (bson_helper_bson_get_string(
	    config,
	    &default_record_status,
	    "defaultRecordStatus",
	    NULL)) {
		LOG(LOG_LV_ERR, "failed in get default record status");
		goto fail;
	}
	if (bson_helper_bson_get_bool(
	    config,
	    &group_preempt,
	    "groupPreempt",
	    NULL)) {
		LOG(LOG_LV_ERR, "failed in get default record status");
		goto fail;
	}
	group_foreach_cb_arg.active_group_members_count = 0;
	group_foreach_cb_arg.status = status;
	group_foreach_cb_arg.config = config;
	group_foreach_cb_arg.address_health_check = address_health_check;
	group_foreach_cb_arg.hostname_health_check = hostname_health_check;
	group_foreach_cb_arg.address_hostname_health_check = address_hostname_health_check;
	group_foreach_cb_arg.default_record_status = default_record_status;
	group_foreach_cb_arg.new_groups = new_groups;
	group_foreach_cb_arg.old_groups = old_groups;
	group_foreach_cb_arg.group_preempt = group_preempt;
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
        group_object_start = 0;
	if (bson_append_long(status, "activeGroupMembersCount", (int64_t)group_foreach_cb_arg.active_group_members_count) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in append active group members count");
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
	bhash_t *tmp_groups = NULL;

	ASSERT(watcher != NULL);
        if (bhash_create(&tmp_groups, DEFAULT_HASH_SIZE, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in create new group status");
                goto fail;
        }
	if (config_manager_get_long(
	    watcher->config_manager,
	    &max_shared_buffer_size,
	    "maxSharedBufferSize",
	    NULL)) {
		LOG(LOG_LV_ERR, "failed in get max shared bufffer size");
		goto fail;
	}
	if (watcher_status_make(
	    &status,
	    max_shared_buffer_size,
	    watcher->config_manager,
	    watcher->domain_map.elements,
	    watcher->remote_address_map.elements,
	    watcher->address_health_check.elements,
	    watcher->hostname_health_check.elements,
	    watcher->address_hostname_health_check.elements,
	    tmp_groups,
            watcher->groups)) {
		LOG(LOG_LV_ERR, "failed in update status");
		goto fail;
	}
        mkstatus = 1;
	/* switch group status */
	if (watcher->groups) {
		bhash_destroy(watcher->groups);
	}
	watcher->groups = tmp_groups;
	/* save status data */
	data = bson_data(&status);
	data_size = bson_size(&status);
	if (data_size > max_shared_buffer_size) {
		LOG(LOG_LV_ERR, "actual data size is too large than max shared buffer size (max = %d, size = %d)", (int)max_shared_buffer_size, data_size);
		goto fail;
	}
	if (shared_buffer_lock_map(watcher->shared_buffer, data_size)) {
		LOG(LOG_LV_ERR, "failed in lock and map of shared buffer");
                goto fail;
	} 
	oshbuf = 1;
	if (shared_buffer_write(watcher->shared_buffer, data, data_size)) {
		LOG(LOG_LV_ERR, "failed in write shared buffer (%s)", DAEMON_BUFFER_FILE_PATH);
	}
	if (shared_buffer_unlock_unmap(watcher->shared_buffer)) {
		LOG(LOG_LV_ERR, "failed in unlock and unmap of shared buffer");
                goto fail;
	} 
	watcher_status_clean(&status);

	return 0;

fail:
	if (oshbuf) {
		shared_buffer_unlock_unmap(watcher->shared_buffer);
	}
	if (mkstatus) {
		watcher_status_clean(&status);
	}
	if (tmp_groups) {
		bhash_destroy(tmp_groups);
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

	ASSERT(watcher != NULL);
	switch (target_type) {
        case TARGET_TYPE_DOMAIN_MAP:
		target = &watcher->domain_map;
		path = "domainMap.pollingInterval";
		break;
        case TARGET_TYPE_REMOTE_ADDRESS_MAP:
		target = &watcher->remote_address_map;
		path = "remoteAddressMap.pollingInterval";
		break;
        case TARGET_TYPE_ADDRESS_HEALTH_CHECK:
		target = &watcher->address_health_check;
		path = "addressHealthCheck.pollingInterval";
		break;
        case TARGET_TYPE_HOSTNAME_HEALTH_CHECK:
		target = &watcher->hostname_health_check;
		path = "hostnameHealthCheck.pollingInterval";
		break;
        case TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK:
		target = &watcher->address_hostname_health_check;
		path = "addressHostnameHealthCheck.pollingInterval";
		break;
	default:
		/* NOTREACHED */
		ABORT("unknown target type");
		return 1;
	}
	if (config_manager_get_long(watcher->config_manager, &interval, path, default_path)) {
		LOG(LOG_LV_ERR, "failed in get polling interval (type = %d)", target_type);
		return 1;
	}
	target->polling_interval.tv_sec = (long)interval;
	evtimer_set(&target->event, watcher_polling_common, target);
	event_priority_set(&target->event, DEFAULT_EVENT_PRIORITY + 10);
	event_base_set(watcher->event_base, &target->event);
	evtimer_add(&target->event, &target->polling_interval);

	return 0;
}

static int
watcher_polling_common_add_element(
    watcher_target_type_t target_type,
    char *key,
    char *value,
    bhash_t *new_elements,
    bhash_t *old_elements)
{
	char buffer[sizeof(map_element_t) + DEFAULT_IO_BUFFER_SIZE];
	watcher_status_element_t new_address_health_check_element, *old_address_health_check_element = NULL;
	watcher_status_element_t new_hostname_health_check_element, *old_hostname_health_check_element = NULL;
	watcher_status_element_t new_address_hostname_health_check_element, *old_address_hostname_health_check_element = NULL;
	map_element_t *map_element;
	v4v6_addr_mask_t addr_mask;
	size_t key_size;
	size_t value_size;

	switch (target_type) {
        case TARGET_TYPE_DOMAIN_MAP:
		key_size = strlen(key) + 1;
		value_size = strlen(value) + 1;
		map_element = (map_element_t *)buffer;
		memcpy(buffer + offsetof(map_element_t, value), value, value_size); 
                if (strspn(key, DOMAIN_CHARS) != key_size - 1) {
			LOG(LOG_LV_INFO, "failed in validate %s entry as domain (type = %d)", key, target_type);
			return 1;
		}
		if (bhash_replace(
		    new_elements,
		    key,
		    strlen(key) + 1,
		    buffer,
		    sizeof(map_element_t) + value_size,
                    NULL,
		    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry (type = %d)", key, target_type);
			return 1;
		}
		break;
        case TARGET_TYPE_REMOTE_ADDRESS_MAP:
		value_size = strlen(value) + 1;
		map_element = (map_element_t *)buffer;
		memcpy(buffer + offsetof(map_element_t, value), value, value_size); 
		if (addrstr_to_addrmask_b(&addr_mask, key)) {
			LOG(LOG_LV_INFO, "failed in convert string to address and mask %s entry (type = %d)", key, target_type);
			return 1;
		}
		if (bhash_replace(
		    new_elements,
		    (const char *)&addr_mask,
		    sizeof(v4v6_addr_mask_t),
		    buffer,
		    sizeof(map_element_t) + value_size,
                    NULL,
		    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry (type = %d)", key, target_type);
			return 1;
		}
		break;
        case TARGET_TYPE_ADDRESS_HEALTH_CHECK:
		key_size = strlen(key) + 1;
		// 古いaddress_health_checkを取得
		new_address_health_check_element.previous_status = 1;
		new_address_health_check_element.preempt_status = 1;
		if (old_elements) {
			if (bhash_get(old_elements, (char **)&old_address_health_check_element, NULL, key, key_size)) {
				// pass
			}
			// previous_status情報とpreempt_status情報を新しいaddress_health_checkに継承
			if (old_address_health_check_element) {
				new_address_health_check_element.previous_status = old_address_health_check_element->current_status;
				new_address_health_check_element.preempt_status = old_address_health_check_element->preempt_status;
			}
		}
		// up/downのチェック
		if (strcasecmp(value, "up") != 0) {
			new_address_health_check_element.current_status = 0;
			new_address_health_check_element.preempt_status = 0;
		} else {
			new_address_health_check_element.current_status = 1;
			// preemptが有効ならば、new_address_health_check_elementのpreempt_statusを変化させたいが、
			// 設定をここで読むのが大変なので別のところで処理している
		}
		// ログ出力
		if (new_address_health_check_element.previous_status == 0 && new_address_health_check_element.current_status == 1) {
			// DOWN TO UP
			LOG(LOG_LV_INFO, "%s status change down to up (record)", key);
		} else if (new_address_health_check_element.previous_status == 1 && new_address_health_check_element.current_status == 0) {
			// UP TO DOWN
			LOG(LOG_LV_INFO, "%s status change up to down (record)", key);
		}
		//データを更新
		if (bhash_replace(
		    new_elements,
		    key,
		    strlen(key) + 1,
		    (char *)&new_address_health_check_element,
		    sizeof(watcher_status_element_t),
		    NULL,
                    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry of health check (type = %d)", key, target_type);
			return 1;	
		}
		break;
        case TARGET_TYPE_HOSTNAME_HEALTH_CHECK:
		key_size = strlen(key) + 1;
		// 古いhostname_health_checkを取得
		new_hostname_health_check_element.previous_status = 1;
		new_hostname_health_check_element.preempt_status = 1;
		if (old_elements) {
			if (bhash_get(old_elements, (char **)&old_hostname_health_check_element, NULL, key, key_size)) {
				// pass
			}
			// previous_status情報とpreempt_status情報を新しいhostname_health_checkに継承
			if (old_hostname_health_check_element) {
				new_hostname_health_check_element.previous_status = old_hostname_health_check_element->current_status;
				new_hostname_health_check_element.preempt_status = old_hostname_health_check_element->preempt_status;
			}
		}
		// up/downのチェック
		if (strcasecmp(value, "up") != 0) {
			new_hostname_health_check_element.current_status = 0;
			new_hostname_health_check_element.preempt_status = 0;
		} else {
			new_hostname_health_check_element.current_status = 1;
			// preemptが有効ならば、new_hostname_health_check_elementのpreempt_statusを変化させたいが、
			// 設定をここで読むのが大変なので別のところで処理している
		}
		// ログ出力
		if (new_hostname_health_check_element.previous_status == 0 && new_hostname_health_check_element.current_status == 1) {
			// DOWN TO UP
			LOG(LOG_LV_INFO, "%s status change down to up (record)", key);
		} else if (new_hostname_health_check_element.previous_status == 1 && new_hostname_health_check_element.current_status == 0) {
			// UP TO DOWN
			LOG(LOG_LV_INFO, "%s status change up to down (record)", key);
		}
		//データを更新
		if (bhash_replace(
		    new_elements,
		    key,
		    strlen(key) + 1,
		    (char *)&new_hostname_health_check_element,
		    sizeof(watcher_status_element_t),
		    NULL,
                    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry of health check (type = %d)", key, target_type);
			return 1;	
		}
		break;
        case TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK:
		key_size = strlen(key) + 1;
		// 古いhostname_health_checkを取得
		new_address_hostname_health_check_element.previous_status = 1;
		new_address_hostname_health_check_element.preempt_status = 1;
		if (old_elements) {
			if (bhash_get(old_elements, (char **)&old_address_hostname_health_check_element, NULL, key, key_size)) {
				// pass
			}
			// previous_status情報とpreempt_status情報を新しいaddress_hostname_health_checkに継承
			if (old_address_hostname_health_check_element) {
				new_address_hostname_health_check_element.previous_status = old_address_hostname_health_check_element->current_status;
				new_address_hostname_health_check_element.preempt_status = old_address_hostname_health_check_element->preempt_status;
			}
		}
		// up/downのチェック
		if (strcasecmp(value, "up") != 0) {
			new_address_hostname_health_check_element.current_status = 0;
			new_address_hostname_health_check_element.preempt_status = 0;
		} else {
			new_address_hostname_health_check_element.current_status = 1;
			// preemptが有効ならば、new_address_hostname_health_check_elementのpreempt_statusを変化させたいが、
			// 設定をここで読むのが大変なので別のところで処理している
		}
		// ログ出力
		if (new_address_hostname_health_check_element.previous_status == 0 && new_address_hostname_health_check_element.current_status == 1) {
			// DOWN TO UP
			LOG(LOG_LV_INFO, "%s status change down to up (record)", key);
		} else if (new_address_hostname_health_check_element.previous_status == 1 && new_address_hostname_health_check_element.current_status == 0) {
			// UP TO DOWN
			LOG(LOG_LV_INFO, "%s status change up to down (record)", key);
		}
		//データを更新
		if (bhash_replace(
		    new_elements,
		    key,
		    strlen(key) + 1,
		    (char *)&new_address_hostname_health_check_element,
		    sizeof(watcher_status_element_t),
		    NULL,
                    NULL)) {
			LOG(LOG_LV_INFO, "failed in replace %s entry of health check (type = %d)", key, target_type);
			return 1;	
		}
		break;
	default:
		/* NOTREACHED */
		ABORT("unknown target type");
		return 1;
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
        case TARGET_TYPE_ADDRESS_HEALTH_CHECK:
                update_value = 0x04;
		break;
        case TARGET_TYPE_HOSTNAME_HEALTH_CHECK:
                update_value = 0x08;
		break;
        case TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK:
                update_value = 0x10;
		break;
	default:
		/* NOTREACHED */
		ABORT("unknown target type");
		return;
	}
	if (!target->reading) {
		if (bhash_create(&target->tmp_elements, DEFAULT_HASH_SIZE, NULL, NULL)) {
			LOG(LOG_LV_INFO, "failed in create new hash");
			target->tmp_elements = NULL;
		}
		target->reading = 1;
	}
	tmp_buffer[0] = '\0';
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
			if (tmp_buffer[0] != '\0' && !string_kv_split_b(&kv, tmp_buffer, " \t")) {
				if (target->tmp_elements) {
					if (watcher_polling_common_add_element(
					    target->type,
					    kv.key,
					    kv.value,
					    target->tmp_elements,
					    target->elements)) {
						LOG(LOG_LV_INFO, "failed in add element (type = %d)", target->type);
					}
				}
			}
		}
		target->remain_buffer_len = 0;
		*exec_flag = EXEC_FL_FINISH;
		watcher->updated |= update_value;
		// switch elements
		target->reading = 0;
		if (target->elements) {
			bhash_destroy(target->elements);
		}
		target->elements = target->tmp_elements;
		target->tmp_elements = NULL;
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
                        if (*line_start == '\0') {
                                break;
                        }
			if (!string_kv_split_b(&kv, line_start, " \t" )) {
				if (target->tmp_elements) {
					if (watcher_polling_common_add_element(
					    target->type,
					    kv.key,
					    kv.value,
					    target->tmp_elements,
					    target->elements)) {
						LOG(LOG_LV_INFO, "failed in add element (type = %d)", target->type);
					}
				}
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
        case TARGET_TYPE_ADDRESS_HEALTH_CHECK:
		path = "addressHealthCheck.executeScript";
		break;
        case TARGET_TYPE_HOSTNAME_HEALTH_CHECK:
		path = "hostnameHealthCheck.executeScript";
		break;
        case TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK:
		path = "addressHostnameHealthCheck.executeScript";
		break;
	default:
		/* NOTREACHED */
		ABORT("unknown target type");
		goto last;
	}
	if (config_manager_get_string(watcher->config_manager, &execute_script, path, NULL)) {
		LOG(LOG_LV_DEBUG, "failed in get script (type = %d)", target->type);
		goto last;
	}
	if (executor_exec(
	    watcher->executor,
	    execute_script,
	    watcher_polling_common_response,
	    target)) {
		LOG(LOG_LV_INFO, "failed in execute script (type = %d)", target->type);
	}
	LOG(LOG_LV_DEBUG, "execute script (type = %d, script=%s)", target->type, execute_script);
last:
	watcher_set_polling_common(watcher, target->type);
}

static int
watcher_set_polling_update_check(
    watcher_t *watcher)
{
	ASSERT(watcher != NULL);

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

	ASSERT(watcher != NULL);

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

static void
watcher_status_foreach_cb(
    void *foreach_cb_arg,
    int idx,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size)
{
	watcher_status_foreach_cb_arg_t *arg = foreach_cb_arg;

	ASSERT(arg != NULL);
	ASSERT(arg->foreach_cb != NULL);
	ASSERT(arg->foreach_cb_arg != NULL);

	arg->foreach_cb(arg->foreach_cb_arg, key);
}

int
watcher_create(
    watcher_t **watcher,
    struct event_base *event_base,
    config_manager_t *config_manager)
{
	watcher_t *new = NULL;
	shared_buffer_t *new_shared_buffer = NULL;
	int shbufopen = 0;
	executor_t *new_executor = NULL;

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
	memset(new, 0, sizeof(watcher_t));
        if (shared_buffer_create(&new_shared_buffer)) {
                goto fail;
        }
        if (shared_buffer_open(new_shared_buffer, DAEMON_BUFFER_FILE_PATH, SHBUF_OFL_WRITE|SHBUF_OFL_READ)) {
                goto fail;
        }
	shbufopen = 1;
        if (executor_create(&new_executor, event_base)) {
                goto fail;
        }
	new->shared_buffer = new_shared_buffer;
	new->domain_map.type = TARGET_TYPE_DOMAIN_MAP;
	new->domain_map.backptr = new;
	new->remote_address_map.type = TARGET_TYPE_REMOTE_ADDRESS_MAP;
	new->remote_address_map.backptr = new;
	new->address_health_check.type = TARGET_TYPE_ADDRESS_HEALTH_CHECK;
	new->address_health_check.backptr = new;
	new->hostname_health_check.type = TARGET_TYPE_HOSTNAME_HEALTH_CHECK;
	new->hostname_health_check.backptr = new;
	new->address_hostname_health_check.type = TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK;
	new->address_hostname_health_check.backptr = new;
	new->executor = new_executor;
	new->event_base = event_base;
	new->config_manager = config_manager;
	*watcher = new;

	return 0;

fail:
	if (new_executor) {
		executor_destroy(new_executor);
	}
	if (shbufopen) {
		shared_buffer_close(new_shared_buffer);
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
        if (watcher->groups) {
		bhash_destroy(watcher->groups);
        }
        if (watcher->domain_map.elements) {
		bhash_destroy(watcher->domain_map.elements);
        }
        if (watcher->remote_address_map.elements) {
		bhash_destroy(watcher->remote_address_map.elements);
        }
        if (watcher->address_health_check.elements) {
		bhash_destroy(watcher->address_health_check.elements);
        }
        if (watcher->hostname_health_check.elements) {
		bhash_destroy(watcher->hostname_health_check.elements);
        }
        if (watcher->address_hostname_health_check.elements) {
		bhash_destroy(watcher->address_hostname_health_check.elements);
        }
	if (watcher->executor) {
		executor_waitpid(watcher->executor);
		executor_destroy(watcher->executor);
	}
	if (watcher->shared_buffer) {
		shared_buffer_close(watcher->shared_buffer);
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
	watcher_set_polling_common(watcher, TARGET_TYPE_ADDRESS_HEALTH_CHECK);
	watcher_set_polling_common(watcher, TARGET_TYPE_HOSTNAME_HEALTH_CHECK);
	watcher_set_polling_common(watcher, TARGET_TYPE_ADDRESS_HOSTNAME_HEALTH_CHECK);
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
	evtimer_del(&watcher->address_health_check.event);
	evtimer_del(&watcher->hostname_health_check.event);
	evtimer_del(&watcher->address_hostname_health_check.event);
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

int
watcher_groups_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg)
{
	watcher_status_foreach_cb_arg_t watcher_status_foreach_cb_arg;
	watcher_status_foreach_cb_arg.foreach_cb = foreach_cb;
	watcher_status_foreach_cb_arg.foreach_cb_arg = foreach_cb_arg;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (bhash_foreach(watcher->groups, watcher_status_foreach_cb, &watcher_status_foreach_cb_arg)) {
		return 1;
	}

	return 0;
}

int
watcher_addresses_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg)
{
	watcher_status_foreach_cb_arg_t watcher_status_foreach_cb_arg;
	watcher_status_foreach_cb_arg.foreach_cb = foreach_cb;
	watcher_status_foreach_cb_arg.foreach_cb_arg = foreach_cb_arg;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (bhash_foreach(watcher->address_health_check.elements, watcher_status_foreach_cb, &watcher_status_foreach_cb_arg)) {
		return 1;
	}

	return 0;
}

int
watcher_hostnames_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg)
{
	watcher_status_foreach_cb_arg_t watcher_status_foreach_cb_arg;
	watcher_status_foreach_cb_arg.foreach_cb = foreach_cb;
	watcher_status_foreach_cb_arg.foreach_cb_arg = foreach_cb_arg;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (bhash_foreach(watcher->hostname_health_check.elements, watcher_status_foreach_cb, &watcher_status_foreach_cb_arg)) {
		return 1;
	}

	return 0;
}

int
watcher_addresses_hostnames_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg)
{
	watcher_status_foreach_cb_arg_t watcher_status_foreach_cb_arg;
	watcher_status_foreach_cb_arg.foreach_cb = foreach_cb;
	watcher_status_foreach_cb_arg.foreach_cb_arg = foreach_cb_arg;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (bhash_foreach(watcher->address_hostname_health_check.elements, watcher_status_foreach_cb, &watcher_status_foreach_cb_arg)) {
		return 1;
	}

	return 0;
}

int
watcher_get_group_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status)
{
	size_t name_size;
	watcher_status_element_t *group_status;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(watcher->groups, (char **)&group_status, NULL, name, name_size)) {
		return 1;
	}
	if (group_status == NULL) {
		return 1;
	}
	*current_status = group_status->current_status;
	*previous_status = group_status->previous_status;
	*preempt_status = group_status->preempt_status;

	return 0;
}

int
watcher_get_address_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status)
{
	size_t name_size;
	watcher_status_element_t *health_status;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(watcher->address_health_check.elements, (char **)&health_status, NULL, name, name_size)) {
		return 1;
	}
	if (health_status == NULL) {
		return 1;
	}
	*current_status = health_status->current_status;
	*previous_status = health_status->previous_status;
	*preempt_status = health_status->preempt_status;

	return 0;
}

int
watcher_get_hostname_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status)
{
	size_t name_size;
	watcher_status_element_t *health_status;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(watcher->hostname_health_check.elements, (char **)&health_status, NULL, name, name_size)) {
		return 1;
	}
	if (health_status == NULL) {
		return 1;
	}
	*current_status = health_status->current_status;
	*previous_status = health_status->previous_status;
	*preempt_status = health_status->preempt_status;

	return 0;
}

int
watcher_get_address_hostname_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status)
{
	size_t name_size;
	watcher_status_element_t *health_status;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(watcher->address_hostname_health_check.elements, (char **)&health_status, NULL, name, name_size)) {
		return 1;
	}
	if (health_status == NULL) {
		return 1;
	}
	*current_status = health_status->current_status;
	*previous_status = health_status->previous_status;
	*preempt_status = health_status->preempt_status;

	return 0;
}


int
watcher_update_group_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status)
{
	size_t name_size;
	watcher_status_element_t *group_status, new_group_status;
	bhash_t *new_elements;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (watcher->groups == NULL) {
		if (bhash_create(&new_elements, DEFAULT_HASH_SIZE, NULL, NULL)) {
			LOG(LOG_LV_ERR, "failed in create new hash");
			return 1;
		}
		watcher->groups = new_elements;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(watcher->groups, (char **)&group_status, NULL, name, name_size)) {
		LOG(LOG_LV_ERR, "failed in get %s entry of group health", name);
		return 1;
	}
	if (group_status == NULL) {
		new_group_status.current_status = current_status;
		new_group_status.previous_status = 1;
		new_group_status.preempt_status = 1;
		if (bhash_put(
		    watcher->groups,
		    name,
		    name_size,
		    (char *)&new_group_status,
	  	    sizeof(watcher_status_element_t))) {
			LOG(LOG_LV_ERR, "failed in put %s entry of group health", name);
			return 1;	
		}
	} else {
		group_status->current_status = current_status;
	}
	LOG(LOG_LV_INFO, "change current status to %s of %s entry of group health ", (current_status) ? "up" : "down", name);

	return 0;
}

static int
watcher_update_common_health_status(
    watcher_t *watcher,
    watcher_target_t *target,
    const char *target_name,
    const char *name,
    int current_status)
{
	size_t name_size;
	watcher_status_element_t *health_status, new_health_status;
	bhash_t *new_elements;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (target->elements == NULL) {
		if (bhash_create(&new_elements, DEFAULT_HASH_SIZE, NULL, NULL)) {
			LOG(LOG_LV_ERR, "failed in create new hash");
			return 1;
		}
		target->elements = new_elements;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(target->elements, (char **)&health_status, NULL, name, name_size)) {
		LOG(LOG_LV_ERR, "failed in get %s entry of %s health", name, target_name);
		return 1;
	}
	if (health_status == NULL) {
		new_health_status.current_status = current_status;
		new_health_status.previous_status = 1;
		new_health_status.preempt_status = 1;
		if (bhash_put(
		    target->elements,
		    name,
		    name_size,
		    (char *)&health_status,
	  	    sizeof(watcher_status_element_t))) {
			LOG(LOG_LV_ERR, "failed in put %s entry of %s health", name, target_name);
			return 1;	
		}
	} else {
		health_status->current_status = current_status;
	}
	LOG(LOG_LV_INFO, "change current status to %s of %s entry of %s health ", (current_status) ? "up" : "down", name, target_name);

	return 0;
}

int
watcher_update_address_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status)
{
	return watcher_update_common_health_status(
	    watcher, &watcher->address_health_check, "address", name, current_status);
}

int
watcher_update_hostname_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status)
{
	return watcher_update_common_health_status(
	    watcher, &watcher->hostname_health_check, "hostname", name, current_status);
}

int
watcher_update_address_hostname_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status)
{
	return watcher_update_common_health_status(
	    watcher, &watcher->address_hostname_health_check, "address_hostname", name, current_status);
}

int
watcher_update_group_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status)
{
	size_t name_size;
	watcher_status_element_t *group_status, new_group_status;
	bhash_t *new_elements;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (watcher->groups == NULL) {
		if (bhash_create(&new_elements, DEFAULT_HASH_SIZE, NULL, NULL)) {
			LOG(LOG_LV_ERR, "failed in create new hash");
			return 1;
		}
		watcher->groups = new_elements;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(watcher->groups, (char **)&group_status, NULL, name, name_size)) {
		LOG(LOG_LV_ERR, "failed in get %s entry of group health", name);
		return 1;
	}
	if (group_status == NULL) {
		new_group_status.current_status = 1;
		new_group_status.previous_status = 1;
		new_group_status.preempt_status = preempt_status;
		if (bhash_put(
		    watcher->groups,
		    name,
		    name_size,
		    (char *)&new_group_status,
	  	    sizeof(watcher_status_element_t))) {
			LOG(LOG_LV_ERR, "failed in put %s entry of group health", name);
			return 1;	
		}
	} else {
		group_status->preempt_status = preempt_status;
	}
	LOG(LOG_LV_INFO, "change preempt status to %s of %s entry of group health ", (preempt_status) ? "up" : "down", name);

	return 0;
}

static int
watcher_update_common_health_preempt_status(
    watcher_t *watcher,
    watcher_target_t *target,
    const char *target_name,
    const char *name,
    int preempt_status)
{
	size_t name_size;
	watcher_status_element_t *health_status, new_health_status;
	bhash_t *new_elements;

	if (watcher == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (target->elements == NULL) {
		if (bhash_create(&new_elements, DEFAULT_HASH_SIZE, NULL, NULL)) {
			LOG(LOG_LV_ERR, "failed in create new hash");
			return 1;
		}
		target->elements = new_elements;
	}
	name_size = strlen(name) + 1;
	if (bhash_get(target->elements, (char **)&health_status, NULL, name, name_size)) {
		LOG(LOG_LV_ERR, "failed in put %s entry of %s health", name, target_name);
		return 1;
	}
	if (health_status == NULL) {
		new_health_status.current_status = 1;
		new_health_status.previous_status = 1;
		new_health_status.preempt_status = preempt_status;
		if (bhash_put(
		    target->elements,
		    name,
		    name_size,
		    (char *)&new_health_status,
	  	    sizeof(watcher_status_element_t))) {
			LOG(LOG_LV_ERR, "failed in put %s entry of %s health", name, target_name);
			return 1;	
		}
	} else {
		health_status->preempt_status = preempt_status;
	}
	LOG(LOG_LV_INFO, "change preempt status to %s of %s entry of %s health ", (preempt_status) ? "up" : "down", name, target_name);

	return 0;
}

int
watcher_update_address_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status)
{
	return watcher_update_common_health_preempt_status(
	    watcher, &watcher->address_health_check, "address", name, preempt_status);
}

int
watcher_update_hostname_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status)
{
	return watcher_update_common_health_preempt_status(
	    watcher, &watcher->hostname_health_check, "hostname", name, preempt_status);
}

int
watcher_update_address_hostname_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status)
{
	return watcher_update_common_health_preempt_status(
	    watcher, &watcher->address_hostname_health_check, "address hostname", name, preempt_status);
}
