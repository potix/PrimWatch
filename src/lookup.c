#include <sys/queue.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>

#include "bson/bson.h"

#include "common_macro.h"
#include "common_define.h"
#include "shared_buffer.h"
#include "bhash.h"
#include "bson_helper.h"
#include "address_util.h"
#include "record.h"
#include "accessa.h"
#include "logger.h"
#include "lookup.h"

// XXXX AAAAレコードはv6の奴返さないといけないや

typedef struct lookup_record_random_foreach_arg lookup_record_random_foreach_arg_t;

struct lookup_params {
        char *shared_buffer_data;
        bson status;
        lookup_type_t lookup_type;
        v4v6_addr_mask_t revaddr_mask;
	char revaddr_str[INET6_ADDRSTRLEN];
	revfmt_type_t revfmt_type;
};

struct lookup_record_random_foreach_arg {
	lookup_t *lookup;
	int idxs[MAX_RECORDS];
	int64_t max_records; 
};

static int
lookup_domain_map(
    lookup_t *lookup,
    char const **group,
    bson_iterator *group_itr,
    int64_t group_select_order)
{
	const char *bin_data;
	size_t bin_data_size;
	bhash_t domain_map;
	char *candidate_group;
	char path[MAX_BSON_PATH_LEN];

	ASSERT(lookup != NULL);
	ASSERT(group != NULL);
	if (*group != NULL && group_select_order != 0)  {
		return 0;
	}
	if (bson_helper_bson_get_binary(&lookup->params->status, &bin_data, &bin_data_size, "domainMap", NULL)) {
		printf("XXX1\n");
		return 1;
	}
	if (bhash_create_wrap_bhash_data(&domain_map, bin_data, bin_data_size)) {
		printf("XXX2\n");
		return 1;
	}
	if (bhash_get(&domain_map, &candidate_group, NULL, lookup->input.name, strlen(lookup->input.name) + 1)) {
		printf("XXX3\n");
		return 1;
	}
	if (candidate_group == NULL) {
		return 0;
	}
	snprintf(path, sizeof(path), "groups.%s", candidate_group);
	if (bson_helper_bson_get_itr(group_itr, &lookup->params->status, path)) {
		printf("XXXX not found group\n");
		// XXX log XXX exist domain map but not exist status
		return 0;
	}
	*group = candidate_group;

	return 0;
}

static int
lookup_remote_address_map(
    lookup_t *lookup,
    char const **group,
    bson_iterator *group_itr,
    int64_t group_select_order)
{
	const char *bin_data;
	size_t bin_data_size;
	bhash_t remote_address_map;
        v4v6_addr_mask_t remoteaddr_mask;
	char *candidate_group;
	char path[MAX_BSON_PATH_LEN];

	ASSERT(lookup != NULL);
	ASSERT(group != NULL);
	if (!lookup->input.remote_address) {
		return 0;
	}
	if (*group != NULL && group_select_order != 1)  {
		return 0;
	}
	if (bson_helper_bson_get_binary(&lookup->params->status, &bin_data, &bin_data_size, "domainMap", NULL)) {
		printf("XXX4\n");
		return 1;
	}
	if (bhash_create_wrap_bhash_data(&remote_address_map, bin_data, bin_data_size)) {
		printf("XXX5\n");
		return 1;
	}
	if (addrstr_to_addrmask(&remoteaddr_mask, lookup->input.remote_address)) {
		printf("XXX6\n");
		return 1;
	}
	while (1) {
		if (bhash_get(&remote_address_map, &candidate_group, NULL, (const char *)(&remoteaddr_mask), sizeof(v4v6_addr_mask_t))) {
			printf("XXX7\n");
			return 1;
		}
		if (candidate_group == NULL) {
			if (decrement_mask_b(&remoteaddr_mask)) {
				break;
			}
			continue;
		}
		snprintf(path, sizeof(path), "groups.%s", candidate_group);
		if (bson_helper_bson_get_itr(group_itr, &lookup->params->status, path)) {
			// XXX log XXX exist domain map but not exist status
			printf("XXX not found group\n");
			return 0;
		}
		*group = candidate_group;
		break;
	}

	return 0;
}

static void
lookup_record_random_foreach(
    void *foreach_cb_arg,
    int idx,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size)
{
	int i;
	lookup_record_random_foreach_arg_t *lookup_record_random_foreach_arg = foreach_cb_arg;
	record_buffer_t *record_buffer;
	lookup_t *lookup;
	
	ASSERT(lookup_record_random_foreach_arg != NULL);
	ASSERT(lookup_record_random_foreach_arg->lookup != NULL);
	ASSERT(idx >= 0);
	ASSERT(key != NULL);
	ASSERT(key_size > 0);
	ASSERT(value != NULL);
	ASSERT(value_size > 0);

	for (i = 0; i < lookup_record_random_foreach_arg->max_records; i++) {
		if (idx == lookup_record_random_foreach_arg->idxs[i]) {
			break;
		}
	}
	if (i == lookup_record_random_foreach_arg->max_records) {
		/* skip */
		return;
	}
	lookup = lookup_record_random_foreach_arg->lookup;
	record_buffer = (record_buffer_t *)value;
	switch (lookup->params->lookup_type) {
	case LOOKUP_TYPE_NATIVE_A:
		lookup->output.entry[i].name = key;
		break;
	case LOOKUP_TYPE_NATIVE_PTR:
		// XXX to convert reverse  addr key
		lookup->output.entry[i].name = key;
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected type of lookup");
	}
	lookup->output.entry[i].class = lookup->input.class;
	lookup->output.entry[i].type = lookup->input.type;
	lookup->output.entry[i].ttl = (unsigned long long)record_buffer->ttl;
	lookup->output.entry[i].id = lookup->input.id;
	lookup->output.entry[i].content = ((char *)record_buffer) + offsetof(record_buffer_t, value);
}

static int
lookup_record_random(
    lookup_t *lookup,
    bson_iterator *group_itr,
    const char *name,
    int64_t record_members_count,
    int64_t max_records)
{
	int i, j;
	int idx;
	char path[MAX_BSON_PATH_LEN];
	const char *bin_data;
	size_t bin_data_size;
	bhash_t bhash;
	lookup_record_random_foreach_arg_t lookup_record_random_foreach_arg = {
		.lookup = lookup,
	};

	ASSERT(lookup != NULL);
	ASSERT(group_itr != NULL);
	ASSERT(name != NULL);
	if (max_records > record_members_count) {
		max_records = record_members_count;
	}
	if (max_records <= 0) {
		/* no record */
		return 0;
	}
	lookup_record_random_foreach_arg.max_records = max_records;
	for(i = 0; i < max_records; i++) {
		while (1) {
			idx = (int)(random() % (int)record_members_count);
			for (j = 0; j < i; j ++) {
				if (lookup_record_random_foreach_arg.idxs[j] == idx) {
					break;
				}
			}
			if (j != i) {
				continue;
			}
			lookup_record_random_foreach_arg.idxs[i] = idx;
			break;
		}
	}
	lookup->output.entry_count = max_records; 
	switch (lookup->params->lookup_type) {
	case LOOKUP_TYPE_NATIVE_A:
		snprintf(path, sizeof(path), "%s.%s", name, "hostnames");
		break;
	case LOOKUP_TYPE_NATIVE_PTR:
		snprintf(path, sizeof(path), "%s.%s", name, "addresses");
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected type of lookup");
	}
	if (bson_helper_itr_get_binary(group_itr, &bin_data, &bin_data_size, path, NULL, NULL)) {
		printf("XXX18\n");
		return 1;
	}
	if (bhash_create_wrap_bhash_data(&bhash, bin_data, bin_data_size)) {
		printf("XXX20\n");
		return 1;
	}
	if (bhash_foreach(&bhash, lookup_record_random_foreach, &lookup_record_random_foreach_arg))  {
		printf("XXX21\n");
		return 1;
	}

	return 0;
}

static int
lookup_record(
    lookup_t *lookup,
    bson_iterator *group_itr)
{
	const char *name;
	int64_t max_records;
	int64_t record_select_algorithm;
	int64_t record_members_count;
	char path[MAX_BSON_PATH_LEN];

	ASSERT(lookup != NULL);
	ASSERT(group_itr != NULL);
	name = bson_iterator_key(group_itr);
	snprintf(path, sizeof(path), "%s.%s", name, "recordSelectAlgorithmValue");
	if (bson_helper_itr_get_long(group_itr, &record_select_algorithm, path, NULL, NULL)) {
		printf("XXX12\n");
		return 1;
	}
	snprintf(path, sizeof(path), "%s.%s", name, "recordMembersCount");
	if (bson_helper_itr_get_long(group_itr, &record_members_count, path, NULL, NULL)) {
		printf("XXX13\n");
		return 1;
	}
	snprintf(path, sizeof(path), "%s.%s", name, "maxRecords");
	if (bson_helper_itr_get_long(group_itr, &max_records, path, NULL, NULL)) {
		printf("XXX14\n");
		return 1;
	}
	switch (record_select_algorithm) {
	case 0: /* random */
		if (lookup_record_random(lookup, group_itr, name, record_members_count, max_records)) {
			printf("XXX15\n");
			return 1;
		}
		break;
	case 1: /* priority */
		break;
	case 2: /* roundrobin */
		break;
	case 3: /* weight */
		break;
	default:
		return 1;
	}

	return 0;
}

static int
lookup_group_random(
	lookup_t *lookup,
	bson_iterator *group_itr,
	int64_t group_members_count)
{
	int idx;

	ASSERT(lookup != NULL);
	ASSERT(group_itr != NULL);
	ASSERT(group_members_count > 0);
	idx = (int)(random() % (int)group_members_count);
	if (bson_helper_bson_get_itr_by_idx(group_itr, &lookup->params->status, "groups", idx)) {
		printf("XXX11\n");
		return 1;
	}

	return 0;
}

static int
lookup_group(
	lookup_t *lookup)
	
{
	int64_t group_select_algorithm;
	int64_t group_members_count;
	bson_iterator group_itr;

	ASSERT(lookup != NULL);
	if (bson_helper_bson_get_long(&lookup->params->status, &group_select_algorithm, "groupSelectAlgorithmValue", NULL)) {
		printf("XXX8\n");
		return 1;
	}
	if (bson_helper_bson_get_long(&lookup->params->status, &group_members_count, "groupMembersCount", NULL)) {
		printf("XXX9\n");
		return 1;
	}
	switch (group_select_algorithm) {
	case 0: /* random */
		if (lookup_group_random(lookup, &group_itr, group_members_count)) {
			printf("XXX10\n");
			return 1;
		}
		break;
	case 1: /* priority */
		break;
	case 2: /* roundrobin */
		break;
	case 3: /* weight */
		break;
	default:
		/* NOREACHED */
		ABORT("unexpected algorithm of group select");
	}
	if (lookup_record(lookup, &group_itr)) {
		printf("XXX10\n");
		return 1;
	}

	return 0;
}

int
lookup_initialize(
    lookup_t *lookup,
    accessa_t *accessa)
{
	if (lookup == NULL ||
	    accessa == NULL) {
		errno = EINVAL;
		return 1;
	}
	memset(lookup, 0, sizeof(lookup_t));
        if (shared_buffer_create(&lookup->accessa_buffer)) {
                return 1;
        }
	lookup->accessa = accessa;

	return 0;
}

int
lookup_finalize(
    lookup_t *lookup)
{
	if (lookup == NULL) {
		errno = EINVAL;
		return 1;
	}
	shared_buffer_destroy(lookup->accessa_buffer);

	return 0;
}

int
lookup_setup_input(
    lookup_t *lookup,
    const char *name,
    const char *class,
    const char *type,
    const char *id,
    const char *remote_address,
    const char *local_address,
    const char *edns_address)
{
	if (lookup == NULL) {
		errno = EINVAL;
		return 1;
	}
	lookup->input.name = name;
	lookup->input.class = class;
	lookup->input.type = type;
	lookup->input.id = id;
	lookup->input.remote_address = remote_address;
	lookup->input.local_address = local_address;
	lookup->input.edns_address = edns_address;

	return 0;
}

int
lookup_native(
    lookup_t *lookup)
{
	int64_t group_select_order;
	const char *group = NULL;
	bson_iterator group_itr;
	lookup_params_t lookup_params;

	if (lookup == NULL) {
		errno = EINVAL;
		return 1;
	}
	lookup->params = &lookup_params;
	if (shared_buffer_read(lookup->accessa->daemon_buffer, &lookup->params->shared_buffer_data, NULL)) {
		LOG(LOG_LV_ERR, "failed in read shared_buffer");
		return 1;
	}
	if (bson_init_finished_data(&lookup->params->status, lookup->params->shared_buffer_data, 0) != BSON_OK) {
		LOG(LOG_LV_ERR, "failed in initialize of bson");
		return 1;
	}
	if (bson_helper_bson_get_long(&lookup->params->status, &group_select_order, "groupSelectOrderValue", NULL)) {
		LOG(LOG_LV_ERR, "failed in get value of group select order");
		return 1;
	}
	if (strcasecmp(lookup->input.type, "A") == 0) {
		lookup->params->lookup_type = LOOKUP_TYPE_NATIVE_A;
		if (lookup_domain_map(lookup, &group, &group_itr, group_select_order)) {
			LOG(LOG_LV_ERR, "failed in get value of group select order");
			return 1;
		}
	} else if (strcmp(lookup->input.type, "PTR") == 0){
		lookup->params->lookup_type = LOOKUP_TYPE_NATIVE_PTR;
		if (revaddrstr_to_addrmask(&lookup->params->revaddr_mask, &lookup->params->revfmt_type, lookup->input.name)) {
			LOG(LOG_LV_ERR, "failed in convert address and mask");
			return 1;
		}
		if (inet_ntop(
		    lookup->params->revaddr_mask.addr.family,
		    &lookup->params->revaddr_mask.addr.in_addr,
		    lookup->params->revaddr_str,
		    sizeof(lookup->params->revaddr_str))) {
			LOG(LOG_LV_ERR, "failed in convert address");
			return 1;
		}
	} else if (strcmp(lookup->input.type, "NS") == 0){
		LOG(LOG_LV_INFO, "NS RECORD");
		return 1;
	} else {
		/* log */
		LOG(LOG_LV_ERR, "unexpected type (%s)", lookup->input.type);
		return 1;
	}
	if (lookup_remote_address_map(lookup, &group, &group_itr, group_select_order)) {
		LOG(LOG_LV_ERR, "failed in lookup of remote address");
		return 1;
	}
	if (group != NULL) {
		if (lookup_record(lookup, &group_itr)) {
			printf("XXXi\n");
			return 1;
		}
	} else {
		if (lookup_group(lookup)) {
			printf("XXXj\n");
			return 1;
		}
	}

	return 0;
}

int
lookup_get_output_len(
    lookup_t *lookup,
    int *output_len)
{
	if (lookup == NULL ||
	    output_len == NULL) {
		errno = EINVAL;
		return 1;
	}
	*output_len = lookup->output.entry_count;

	return 0;
}

int
lookup_output_foreach(
    lookup_t *lookup,
    void (*output_foreach_cb)(
        void *output_foreach_cb_arg,
        const char *name,
        const char *class,
        const char *type,
        unsigned long long ttl,
        const char *id,
        const char *content),
    void *output_foreach_cb_arg)
{
	int i;

	if (lookup == NULL ||
	    output_foreach_cb == NULL) {
		errno = EINVAL;
		return 1;
	}
	for (i = 0; i < lookup->output.entry_count; i++) {
		output_foreach_cb(
		    output_foreach_cb_arg,
		    lookup->output.entry[i].name,
		    lookup->output.entry[i].class,
		    lookup->output.entry[i].type,
		    lookup->output.entry[i].ttl,
		    lookup->output.entry[i].id,
		    lookup->output.entry[i].content);
	}

	return 0;
}
	
/*
	memo 

        { BSON_LONG, "groupMemberCount" },
        { BSON_LONG, "groupSelectAlgorithmValue" }
	
	    groupselectalgorithm検索チェック
	        random
		    groupMembercount取得
                    random % groupMemberCount
		    n番目のgroup取得
		    foreach() {
			n番目のとき
			    maxreocrd数
                            record数取得
                            record検索アルゴリズム
				random
                                   for (recprd数文 < 0) {
				       random % recor数
				   }
				   foreach() {
					候補番号のとき
				   }
			 	rr
				   for record数　{
				       rr_index + 1 % record数	
				   }
				   foreach() {
					候補番号のとき
				   }
				priority
				   foreach() {
					priority低いのをrecord数文確保
				   }
				   foreach() {
					候補番号のとき
				   }
				weight
				   foreach() {
					weight低いのをrecord数文確保
					accessabufferのweight足しておく
				   }
				   foreach() {
					候補番号のとき
				   }
		    }
	        roudrobin
		    groupMembercount取得
                    accessabufferopen
		    groupの情報取得
                    groupの情報なければ新規
                    groupのrr_idxを取得
		    rr_idx + 1 % groupMemberCount
		    foreach() {
			n番目のとき
                            record検索アルゴリズム
		    }
                    accessabufferclose
	        priority
                    foreach() {
                        priorityが一番でかいやつ
                            record検索アルゴリズム
		    }
	        weight
                    accessabufferopen
                    foreach {
                       accessaのweightが一番小さいやつn番目
                       accessaバッファになかったらあらたに追加
                       weight足しておく
                    }
		    foreach() {
			n番目のとき
                            record検索アルゴリズム
		    }
                    accessabufferclose

]
	lookアップ処理
	
	if (shared_bufer_rwopen(accessa->accessa_buffer, ACCESSA_BUFFER_FILE_PATH)) {
		return 1;
	}
	shared_bufer_read
	現在のaccessa情報から該当エントリをピックアップ
	
	shared_bufer_write
	
	if (shared_bufer_rwopen(accessa->accessa_buffer, ACCESSA_BUFFER_FILE_PATH)) {
		return 1;
	}
	
*/
