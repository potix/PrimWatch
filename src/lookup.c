#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>

#include "bson/bson.h"

#include "common_macro.h"
#include "common_define.h"
#include "shared_buffer.h"
#include "bhash.h"
#include "bson_helper.h"
#include "string_util.h"
#include "address_util.h"
#include "record.h"
#include "accessa.h"
#include "logger.h"
#include "lookup.h"

#define INITIAL_MAX_PRIORITY (0xFFFFFFFF)

typedef struct lookup_record_match_foreach_arg lookup_record_match_foreach_arg_t;
typedef struct lookup_record_roundrobin_cb_arg lookup_record_roundrobin_cb_arg_t;
typedef struct lookup_group_priority_foreach_arg lookup_group_priority_foreach_arg_t;
typedef struct lookup_group_roundrobin_cb_arg lookup_group_roundrobin_cb_arg_t;

struct lookup_params {
        char *shared_buffer_data;
        bson status;
        lookup_type_t lookup_type;
        v4v6_addr_mask_t revaddr_mask;
	char revaddr_str[INET6_ADDRSTRLEN];
	revfmt_type_t revfmt_type;
};

struct lookup_record_match_foreach_arg {
	lookup_t *lookup;
	int64_t record_members_count; 
	int64_t record_select_algorithm;
	int record_rr_idx;
};

struct lookup_record_roundrobin_cb_arg {
	lookup_t *lookup;
	int64_t max_records;
	int64_t record_members_count;
	int64_t record_select_algorithm;
	bhash_t *target;
	const char *name;
};

struct lookup_group_priority_foreach_arg {
	bson_iterator *group_itr;
	int64_t max_priority; 
};

struct lookup_group_roundrobin_cb_arg {
	bson_iterator *group_itr;
	int64_t group_members_count;
};


static int
output_entry_cmp(const void *p1, const void *p2)
{
	lookup_output_entry_t *entry1 = (lookup_output_entry_t *)p1;
	lookup_output_entry_t *entry2 = (lookup_output_entry_t *)p2;

        return entry1->sort_value - entry2->sort_value;
}

static void
lookup_accessa_status_record_free(
    void *free_cb_arg,
    char *key,
    size_t key_size,
    char *value,
    size_t value_size)
{
	/* nothing to do */
}

static void
lookup_accessa_status_group_free(
    void *free_cb_arg,
    char *key,
    size_t key_size,
    char *value,
    size_t value_size)
{
	/* nothing to do */
}

static int
lookup_accessa_status_find(
    accessa_status_group_t **accessa_status_group,
    accessa_status_record_t **accessa_status_record,
    accessa_status_t *accessa_status,
    const char *group,
    const char *record)
{
	blist_t group_blist;
	blist_t record_blist;
	char *ptr;

	ASSERT(accessa_status_group != NULL);
	ASSERT(accessa_status_record != NULL);
	ASSERT(accessa_status != NULL);
	ASSERT(group != NULL);
	*accessa_status_group = NULL;
	if (accessa_status_record) {
		*accessa_status_record = NULL;
	}
	if (blist_create_wrap_bhash_data(
	    &group_blist,
	    ((char *)accessa_status) + offsetof(accessa_status_t, groups_data),
	    accessa_status->groups_data_size)) {
		LOG(LOG_LV_ERR, "failed in create blist of status of group of accessa");
		return 1;
	}
	if (blist_get(
	    &group_blist,
	    &ptr,
	    NULL,
	    group,
	    strlen(group) + 1)) {
		LOG(LOG_LV_ERR, "failed in get group from blist of status of group of accessa (%s)", group);
		return 1;
	}
	*accessa_status_group = (accessa_status_group_t *)ptr;
	if (*accessa_status_group == NULL) {
		LOG(LOG_LV_ERR, "not found group in blist of status of group of accessa (%s)", group);
		return 1;
	}
	if (!record || !accessa_status_record) {
		return 0;
	}
	if (blist_create_wrap_bhash_data(
	    &record_blist,
	    ((char *)(*accessa_status_group)) + offsetof(accessa_status_group_t, records_data),
	    (*accessa_status_group)->records_data_size)) {
		LOG(LOG_LV_ERR, "failed in create blist of status of group of accessa");
		return 1;
	}
	if (blist_get(
	    &record_blist,
	    &ptr,
	    NULL,
	    record,
	    strlen(record) + 1)) {
		LOG(LOG_LV_ERR, "failed in get record from blist of status of record of accessa (%s)", record);
		return 1;
	}
	*accessa_status_record = (accessa_status_record_t *)ptr;
	if (*accessa_status_record == NULL) {
		LOG(LOG_LV_ERR, "not found record in blist of status of record of accessa (%s)", record);
		return 1;
	}

	return 0;
}

static int
lookup_accessa_status_group_create(
	accessa_status_group_t **accessa_status_group,
	const char *record)
{
	accessa_status_record_t accessa_status_record;
	accessa_status_group_t *new = NULL;
	blist_t *blist = NULL;
	char *list_data;
	size_t list_data_size;

	ASSERT(accessa_status_group != NULL);
	// リストを作る
	if (blist_create(&blist, lookup_accessa_status_record_free, NULL)) {
		LOG(LOG_LV_ERR, "failed in create blist of status of record of accessa");
		goto fail;
	}
	if (record) {
		// レコードがある場合はレコードに属するデータを登録する
		accessa_status_record.record_weight = 0; /* XXXX weight */
		if (blist_put(
		    blist,
		    record,
		    strlen(record) + 1,
		    (const char *)&accessa_status_record,
		    sizeof(accessa_status_record))) {
			LOG(LOG_LV_ERR, "failed in put status of record of accessa (%s)", record);
			goto fail;
		}
	}
	// bitmapを抜出する
	if (blist_get_blist_data(blist, &list_data, &list_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of blist of status of record of accessa");
		goto fail;
	}
        // 確保した領域にコピー抽出したbitmapをコピー
	new = malloc(sizeof(accessa_status_group_t) + list_data_size);
	if (new == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate memory for status of record of accessa");
		goto fail;
	}
	new->record_rr_idx = 0;
	new->group_weight = 0; /* XXXX weight */
	new->records_data_size = list_data_size;
	memcpy(((char *)new) + offsetof(accessa_status_group_t, records_data), list_data, list_data_size);
        // 不要なのでリストは消す
	if (blist_destroy(blist)) {
		LOG(LOG_LV_ERR, "failed in destroy blist of status of record of accessa");
		goto fail;
	}
	*accessa_status_group = new;

	return 0;
fail:

	if (blist) {
		blist_destroy(blist);
	}
	free(new);

	return 1;
}

static void
lookup_accessa_status_group_destroy(
	accessa_status_group_t *accessa_status_group)
{
	ASSERT(accessa_status_group != NULL);
	free(accessa_status_group);
}

static int
lookup_accessa_status_create(
    accessa_status_t **accessa_status,
    const char *group,
    const char *record)
{
	accessa_status_t *new = NULL;
	accessa_status_group_t *accessa_status_group = NULL;
	blist_t *blist = NULL;
	char *list_data;
	size_t list_data_size;

	ASSERT(accessa_status != NULL);
	// リスト構造を作る
	if (blist_create(&blist, lookup_accessa_status_group_free, NULL)) {
		LOG(LOG_LV_ERR, "failed in create blist of status of group of accessa");
		goto fail;
	}
	// groupが見つかっている場合、グループに属するデータも作る
	if (group) {
		// レコード情報を作る
		if (lookup_accessa_status_group_create(&accessa_status_group, record)) {
			LOG(LOG_LV_ERR, "failed in create status of group of accessa");
			goto fail;
		}
		// リスト構造にレコード情報を入れる
		if (blist_put(
		    blist,
		    group,
		    strlen(group) + 1,
		    (char *)accessa_status_group,
		    sizeof(accessa_status_group_t) + accessa_status_group->records_data_size)) {
			LOG(LOG_LV_ERR, "failed in put status of group of accessa (%s)", group);
			goto fail;
		}
		lookup_accessa_status_group_destroy(accessa_status_group);
		accessa_status_group = NULL;
	}
	// bitmapを取り出し
	if (blist_get_blist_data(blist, &list_data, &list_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data from blist of status of accessa");
		goto fail;
	}
	// 確保したメモリに取り出したbitmapをコピー
	new = malloc(sizeof(accessa_status_t) + list_data_size);
	if (new == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate memory for status of accessa");
		goto fail;
	}
	new->group_rr_idx = 0;
	new->groups_data_size = list_data_size;
	memcpy(((char *)new) + offsetof(accessa_status_t, groups_data), list_data, list_data_size);
	// 不要になったリストを削除
	if (blist_destroy(blist)) {
		LOG(LOG_LV_ERR, "failed in destroy blist of status of group of acessa");
		goto fail;
	}
	*accessa_status = new;

	return 0;

fail:
	if (accessa_status_group) {
		lookup_accessa_status_group_destroy(accessa_status_group);
	}
	if (blist) {
		blist_destroy(blist);
	}
	free(new);

	return 1;
}

static void
lookup_accessa_status_destroy(
    accessa_status_t *accessa_status)
{
	ASSERT(accessa_status != NULL);
	free(accessa_status);
}

static int
lookup_accessa_status_add_record(
    accessa_status_group_t **new_accessa_status_group,
    accessa_status_group_t *accessa_status_group,
    const char *record)
{
	blist_t *blist = NULL;
	accessa_status_group_t *new = NULL;
	accessa_status_record_t accessa_status_record;
	char *ptr;
	char *list_data;
	size_t list_data_size;

	ASSERT(new_accessa_status_group != NULL);
	ASSERT(accessa_status_group != NULL);
	// クローンを作成
	if (blist_clone(
	    &blist,
	    ((char *)accessa_status_group) + offsetof(accessa_status_group_t, records_data))) {
		LOG(LOG_LV_ERR, "failed in create blist of status of record of accessa");
		return 1;
	}
	if (record) {
		// レコードが存在する場合、レコードの情報を引っ張る
		if (blist_get(
		    blist,
		    &ptr,
		    NULL,
		    record,
		    strlen(record) + 1)) {
			LOG(LOG_LV_ERR, "failed in get from blist of status of record of accessa (%s)", record);
			return 1;
		}
		// レコードが無ければレコード情報を追加
		if (ptr == NULL) {
			accessa_status_record.record_weight = 0; /* XXX weight */
			if (blist_put(
			    blist,
			    record,
			    strlen(record) + 1,
			    (char *)&accessa_status_record,
			    sizeof(accessa_status_record))) {
				LOG(LOG_LV_ERR, "failed in put status of record of accessa (%s)", record);
				goto fail;
			}
		}
	}
	// bitmap領域を取り出す
	if (blist_get_blist_data(blist, &list_data, &list_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data of blist of status of record of accessa");
		goto fail;
	}
	// 新たに確保したメモリ領域にbitmapをコピー
	new = malloc(sizeof(accessa_status_group_t) + list_data_size);
	if (new == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate memory for status of record of accessa");
		goto fail;
	}
	new->record_rr_idx = accessa_status_group->record_rr_idx;
	new->group_weight = accessa_status_group->group_weight; /* XXXX weight */
	new->records_data_size = list_data_size;
	memcpy(((char *)new) + offsetof(accessa_status_group_t, records_data), list_data, list_data_size);
	// 不要なリストを削除
	if (blist_destroy(blist)) {
		LOG(LOG_LV_ERR, "failed in destroy blist of status of record of accessa");
		goto fail;
	}
	*new_accessa_status_group = new;
	
	return 0;

fail:
	if (blist) {
		blist_destroy(blist);
	}
	free(new);

	return 1;
}

static int
lookup_accessa_status_add_group(
    accessa_status_t **new_accessa_status,
    accessa_status_t *accessa_status,
    const char *group,
    const char *record)
{
	blist_t *blist = NULL;
	accessa_status_t *new = NULL;
	accessa_status_group_t *new_accessa_status_group = NULL;
	accessa_status_group_t *accessa_status_group;
	char *list_data;
	size_t list_data_size;
	char *ptr;
	int group_str_size;

	ASSERT(new_accessa_status != NULL);
	ASSERT(accessa_status != NULL);
	ASSERT(group != NULL);
	// クローンをつくる
	if (blist_clone(
	    &blist,
	    ((char *)accessa_status) + offsetof(accessa_status_t, groups_data))) {
		LOG(LOG_LV_ERR, "failed in clone blist of status of accessa");
		goto fail;
	}
        // 該当グループ情報を取り出す
	group_str_size = strlen(group) + 1;
	if (blist_get(
	    blist,
	    &ptr,
	    NULL,
	    group,
	    group_str_size)) {
		LOG(LOG_LV_ERR, "failed in get from blist of status of accessa (%s)", group);
		goto fail;
	}
	// グループが存在しない場合はグループを作成
	if (ptr == NULL) {
		if (lookup_accessa_status_group_create(&new_accessa_status_group, record)) {
			LOG(LOG_LV_ERR, "failed in create status of group of acessa");
			goto fail;
		}
	} else {
		// グループが存在する場合はレコード情報を新規に作成
		accessa_status_group = (accessa_status_group_t *)ptr;
		if (lookup_accessa_status_add_record(&new_accessa_status_group, accessa_status_group, record)) {
			LOG(LOG_LV_ERR, "failed in create status of group of acessa");
			goto fail;
		}
		// 古いグループ情報を削除
		if (blist_delete(blist, group, group_str_size)) {
			LOG(LOG_LV_ERR, "failed in delete group from blist of status of group of acessa (%s)", group);
			goto fail;
		}
		/* XXXX blist shrink */
	}
	// 新しいグループ情報を追加
	if (blist_put(
	    blist,
	    group,
	    strlen(group) + 1,
	    (char *)new_accessa_status_group,
	    sizeof(accessa_status_group_t) + new_accessa_status_group->records_data_size)) {
		LOG(LOG_LV_ERR, "failed in put status of group of acessa (%s)", group);
		goto fail;
	}
	// 不要なaccessa status groupを削除 
	lookup_accessa_status_group_destroy(new_accessa_status_group);
        // bitmapデータの取り出し
	if (blist_get_blist_data(blist, &list_data, &list_data_size)) {
		LOG(LOG_LV_ERR, "failed in get data from blist of status of accessa");
		goto fail;
	}
	// 取り出したbitmapを新しい領域にコピー
	new = malloc(sizeof(accessa_status_t) + list_data_size);
	if (new == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate memory for status of accessa");
		goto fail;
	}
	new->group_rr_idx = accessa_status->group_rr_idx;
	new->groups_data_size = list_data_size;
	memcpy(((char *)new) + offsetof(accessa_status_t, groups_data), list_data, list_data_size);
	// 不要なリストを削除
	if (blist_destroy(blist)) {
		LOG(LOG_LV_ERR, "failed in destroy blist of status of group of acessa");
		goto fail;
	}
	blist = NULL;
	*new_accessa_status = new;

	return 0;

fail:
	if (new_accessa_status_group) {
		lookup_accessa_status_group_destroy(new_accessa_status_group);
	}
	if (blist) {
		blist_destroy(blist);
	}
	free(new);
	
	return 1;
}

static int
lookup_accessa_status_handle(
    lookup_t *lookup,
    int handler_cb(
	lookup_t *lookup,
        void *handler_cb_arg,
        accessa_status_t **accessa_status,
        int *need_free_accessa_status,
	int *need_rewrite_accessa_status),
    void *handler_cb_arg)
{
	int lock = 0;
	int rmap = 0;
	int wmap = 0;
	accessa_status_t *accessa_status = NULL;
	int need_free_accessa_status = 0;
	int need_rewrite_accessa_status = 0;
	size_t write_size;

	ASSERT(lookup != NULL);
	ASSERT(handler_cb != NULL);
	ASSERT(handler_cb_arg != NULL);
	if (shared_buffer_lock(lookup->accessa->accessa_buffer, SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "failed in lock shared buffer");
		goto fail;
	}
	lock = 1;
	if (shared_buffer_rmap(lookup->accessa->accessa_buffer)) {
		LOG(LOG_LV_ERR, "failed in map in read buffer");
		goto fail;
	}
	rmap = 1;
	// コールバックハンドラを呼び出す
	if (handler_cb(
	    lookup,
	    handler_cb_arg,
	    &accessa_status,
	    &need_free_accessa_status,
	    &need_rewrite_accessa_status)) {
		LOG(LOG_LV_ERR, "failed in process callback");
		goto fail;
	}
	// handler callbackでaccessa_statusがNULLになっている場合はエラー
	if (accessa_status == NULL) {
		LOG(LOG_LV_ERR, "accessa status is NULL");
		goto fail;
	}
	write_size = sizeof(accessa_status_t) + accessa_status->groups_data_size;
	if (shared_buffer_runmap(lookup->accessa->accessa_buffer)) {
		LOG(LOG_LV_ERR, "failed in unmap accessa buffer with reading");
		goto fail;
	}
	rmap = 0;
	// accessa_statusの再書き込みが必要な場合
	if (need_rewrite_accessa_status) {
		if (shared_buffer_wmap(lookup->accessa->accessa_buffer, write_size)) {
			LOG(LOG_LV_ERR, "failed in map accessa buffer with writing");
			goto fail;
		}
		wmap = 1;
		if (shared_buffer_write(lookup->accessa->accessa_buffer, (char *)accessa_status, write_size)) {
			LOG(LOG_LV_ERR, "failed in write to accessa buffer");
			goto fail;
		}
		if (shared_buffer_wunmap(lookup->accessa->accessa_buffer)) {
			LOG(LOG_LV_ERR, "failed in unmap accessa buffer with reading");
			goto fail;
		}
	}
	wmap = 0;
	if (shared_buffer_unlock(lookup->accessa->accessa_buffer)) {
		LOG(LOG_LV_ERR, "failed in unlock accessa buffer");
		goto fail;
	}
	lock = 0;
	// accessaステータスのfreeが必要な場合
	if (need_free_accessa_status) {
		lookup_accessa_status_destroy(accessa_status);
	}
	accessa_status = NULL;

	return 0;
fail:

	if (rmap) {
		shared_buffer_runmap(lookup->accessa->accessa_buffer);
	}	
	if (wmap) {
		shared_buffer_wunmap(lookup->accessa->accessa_buffer);
	}	
	if (lock) {
		shared_buffer_unlock(lookup->accessa->accessa_buffer);
	}	
	if (need_free_accessa_status && accessa_status) {
		lookup_accessa_status_destroy(accessa_status);
	}

	return 1;
}

static int
lookup_domain_map(
    lookup_t *lookup,
    char const **group,
    bson_iterator *group_itr)
{
	const char *bin_data;
	size_t bin_data_size;
	bhash_t domain_map;
	char *tmp_name_ptr, tmp_name[NI_MAXHOST];
        v4v6_addr_mask_t tmp_addr_mask;
	char *candidate_group;
	char path[MAX_BSON_PATH_LEN];

	ASSERT(lookup != NULL);
	ASSERT(group != NULL);
	if (*group != NULL)  {
		return 0;
	}
       	// domainMapのデータを取り出す
	if (bson_helper_bson_get_binary(&lookup->params->status, &bin_data, &bin_data_size, "domainMap", NULL)) {
		LOG(LOG_LV_ERR, "failed in get domain map");
		return 1;
	}
	if (bhash_create_wrap_bhash_data(&domain_map, bin_data, bin_data_size)) {
		LOG(LOG_LV_ERR, "failed in create bhash");
		return 1;
	}
       	if (lookup->params->lookup_type == LOOKUP_TYPE_NATIVE_A ||
            lookup->params->lookup_type == LOOKUP_TYPE_NATIVE_AAAA) {
		strlcpy(tmp_name, lookup->input.name, sizeof(tmp_name));
		tmp_name_ptr = tmp_name;
		// domainMapからグループを取り出す
		while (1) {
			if (bhash_get(&domain_map, &candidate_group, NULL, tmp_name_ptr, strlen(tmp_name_ptr) + 1)) {
				LOG(LOG_LV_ERR, "failed in get group from bhash");
				return 1;
			}
			if (candidate_group == NULL) {
				if (decrement_domain_b(&tmp_name_ptr)) {
					break;
				}
				continue;
			}
			snprintf(path, sizeof(path), "groups.%s", candidate_group);
			if (bson_helper_bson_get_itr(group_itr, &lookup->params->status, path)) {
				LOG(LOG_LV_WARNING, "found group in domain map, but not exist group in config (%s)", candidate_group);
				return 0;
			}
			*group = candidate_group;
			break;
		}
	} else if (lookup->params->lookup_type == LOOKUP_TYPE_NATIVE_PTR) {
		memcpy(&tmp_addr_mask, &lookup->params->revaddr_mask, sizeof(tmp_addr_mask));
		// domainMapからグループを取り出す
		while (1) {
			if (bhash_get(&domain_map, &candidate_group, NULL, (char *)&tmp_addr_mask, sizeof(tmp_addr_mask))) {
				LOG(LOG_LV_ERR, "failed in get group from bhash");
				return 1;
			}
			if (candidate_group == NULL) {
				if (decrement_mask_b(&tmp_addr_mask)) {
					break;
				}
				continue;
			}
			snprintf(path, sizeof(path), "groups.%s", candidate_group);
			if (bson_helper_bson_get_itr(group_itr, &lookup->params->status, path)) {
				LOG(LOG_LV_WARNING, "found group in domain map, but not exist group in config (%s)", candidate_group);
				return 0;
			}
			*group = candidate_group;
			break;
		}
	}

	return 0;
}

static int
lookup_remote_address_map(
    lookup_t *lookup,
    char const **group,
    bson_iterator *group_itr)
    
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
	if (*group != NULL)  {
		return 0;
	}
	// remoteAddressMapの情報を取得
	if (bson_helper_bson_get_binary(&lookup->params->status, &bin_data, &bin_data_size, "remoteAddressMap", NULL)) {
		LOG(LOG_LV_ERR, "failed in get remote_address_map");
		return 1;
	}
	if (bhash_create_wrap_bhash_data(&remote_address_map, bin_data, bin_data_size)) {
		LOG(LOG_LV_ERR, "failed in create bhash");
		return 1;
	}
	if (addrstr_to_addrmask(&remoteaddr_mask, lookup->input.remote_address)) {
		LOG(LOG_LV_ERR, "failed in convert address and mask\n");
		return 1;
	}
	while (1) {
		if (bhash_get(&remote_address_map, &candidate_group, NULL, (const char *)(&remoteaddr_mask), sizeof(v4v6_addr_mask_t))) {
			LOG(LOG_LV_ERR, "failed in get remote address from remote address map\n");
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
			LOG(LOG_LV_WARNING, "found group in remote address map, but not exist group in config (%s)", candidate_group);
			return 0;
		}
		*group = candidate_group;
		break;
	}

	return 0;
}

static void
lookup_record_match_foreach(
    void *foreach_cb_arg,
    int idx,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size)
{
	int decrement_level = 1;
	lookup_record_match_foreach_arg_t *lookup_record_match_foreach_arg = foreach_cb_arg;
	record_buffer_t *record_buffer;
	lookup_t *lookup;
        char *tmp_name_ptr, tmp_name[NI_MAXHOST];
	size_t tmp_name_size;
        v4v6_addr_mask_t tmp_addr_mask;
	int match = 0;
	int64_t record_members_count, record_select_algorithm;
	int record_rr_idx;
	
	ASSERT(lookup_record_match_foreach_arg != NULL);
	ASSERT(lookup_record_match_foreach_arg->lookup != NULL);
	ASSERT(idx >= 0);
	ASSERT(key != NULL);
	ASSERT(key_size > 0);
	ASSERT(value != NULL);
	ASSERT(value_size > 0);

	lookup = lookup_record_match_foreach_arg->lookup;
	record_members_count = lookup_record_match_foreach_arg->record_members_count;
	record_select_algorithm = lookup_record_match_foreach_arg->record_select_algorithm;
	record_rr_idx = lookup_record_match_foreach_arg->record_rr_idx;
	record_buffer = (record_buffer_t *)value;
	switch (lookup->params->lookup_type) {
	case LOOKUP_TYPE_NATIVE_A:
	case LOOKUP_TYPE_NATIVE_AAAA:
		// ドメインが一致するものを探す
		strlcpy(tmp_name, lookup->input.name, sizeof(tmp_name));
		tmp_name_ptr = tmp_name;
		while (1) {
			tmp_name_size = strlen(tmp_name_ptr) + 1;
			if (key_size == tmp_name_size
			     && strncmp(key, tmp_name_ptr, tmp_name_size) == 0) {
				strlcpy(
				    lookup->output.entry[lookup->output.entry_count].name,
				    key,
				    sizeof(lookup->output.entry[lookup->output.entry_count].name));
				match = 1;
				break;
			}
			// ここで、レベルを上げながらチェック
			if (decrement_domain_b(&tmp_name_ptr)) {
				break;
			}
			decrement_level++;
		}
		break;
	case LOOKUP_TYPE_NATIVE_PTR:
		// アドレスが一致するものを探す。
		memcpy(&tmp_addr_mask, &lookup->params->revaddr_mask, sizeof(tmp_addr_mask));
		while (1) {
			// アドレス構造体をチェックして、それをrevaddrフォーマットにして返す
			if (sizeof(tmp_addr_mask) == sizeof(record_buffer->addr_mask)
			    && memcmp(&tmp_addr_mask, &record_buffer->addr_mask, sizeof(tmp_addr_mask)) == 0) {
				addrmask_to_revaddrstr(
				    lookup->output.entry[lookup->output.entry_count].name,
				    sizeof(lookup->output.entry[lookup->output.entry_count].name),
				    &record_buffer->addr_mask,
				    lookup->params->revfmt_type);
				match = 1;
				break;
			}
			// ここで、maskを上げながらチェック
			if (decrement_mask_b(&tmp_addr_mask)) {
				break;
			}
			decrement_level++;
		}
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected type of lookup");
	}
	// 一致してる場合は情報を細かい情報を取得
	if (match) {
		switch (record_select_algorithm) {
		case 0: /* random*/
			// プライオリティの値をそのまま流用
			lookup->output.entry[lookup->output.entry_count].sort_value = rand();
			break;
		case 1: /* priority */
			// プライオリティの値をそのまま流用
			lookup->output.entry[lookup->output.entry_count].sort_value = record_buffer->record_priority;
			break;
		case 2: /* roundrobin */
			// ロンゲストマッチ + roundrobinになるようにsort_valueを調整
			lookup->output.entry[lookup->output.entry_count].sort_value = (MAX_RECORDS * decrement_level) + (idx + (record_members_count - record_rr_idx));
			break;
		case 3: /* weight */
			/* XXXXX */
			lookup->output.entry[lookup->output.entry_count].sort_value = 0;
			break;
		default:
			/* NOTREACHED */
			ABORT("unexpected algorithm of group select");
			return;
		}
		lookup->output.entry[lookup->output.entry_count].class = lookup->input.class;
		lookup->output.entry[lookup->output.entry_count].type = lookup->input.type;
		lookup->output.entry[lookup->output.entry_count].ttl = (unsigned long long)record_buffer->ttl;
		lookup->output.entry[lookup->output.entry_count].id = lookup->input.id;
		lookup->output.entry[lookup->output.entry_count].content = ((char *)record_buffer) + offsetof(record_buffer_t, value);
		lookup->output.entry_count++;
	}
}

static int
lookup_record_basic(
    lookup_t *lookup,
    int64_t max_records,
    int64_t record_members_count,
    bhash_t *target,
    int64_t record_select_algorithm)
{
	lookup_record_match_foreach_arg_t lookup_record_match_foreach_arg = {
		.lookup = lookup,
		.record_members_count = record_members_count,
		.record_select_algorithm = record_select_algorithm,
		.record_rr_idx = 0
	};

	ASSERT(lookup != NULL);
	ASSERT(target != NULL);

	// マッチするものを取り出す
	if (bhash_foreach(target, lookup_record_match_foreach, &lookup_record_match_foreach_arg))  {
		LOG(LOG_LV_ERR, "failed in foreach of bhash");
		return 1;
	}
	// マッチしたもののsort_valueを小さい順に並べる
	qsort(lookup->output.entry, lookup->output.entry_count, sizeof(lookup_output_entry_t), output_entry_cmp);
	// max_record分を超過しているものは無かったことにする
	if (lookup->output.entry_count > max_records) {
		lookup->output.entry_count = max_records;
	}

	return 0;
}

static int
lookup_record_roundrobin_cb(
    lookup_t *lookup,
    void *handler_cb_arg,
    accessa_status_t **accessa_status,
    int *need_free_accessa_status,
    int *need_rewrite_accessa_status)
{
	accessa_status_t *new_accessa_status;
	accessa_status_t *old_accessa_status;
	char *buffer_data = NULL;
	lookup_record_roundrobin_cb_arg_t *lookup_record_roundrobin_cb_arg = handler_cb_arg;
	accessa_status_group_t *accessa_status_group = NULL;
	accessa_status_record_t *accessa_status_record = NULL;
	lookup_record_match_foreach_arg_t lookup_record_match_foreach_arg = {
		.lookup = lookup,
		.record_members_count = lookup_record_roundrobin_cb_arg->record_members_count,
		.record_select_algorithm = lookup_record_roundrobin_cb_arg->record_select_algorithm
	};

        if (shared_buffer_read(lookup->accessa->accessa_buffer, &buffer_data, NULL)) {
                LOG(LOG_LV_ERR, "failed in read from accessa buffer");
                return 1;
        }
	if (buffer_data == NULL) {
		if (lookup_accessa_status_create(
		    &new_accessa_status,
		    lookup_record_roundrobin_cb_arg->name,
		    NULL)) {
			LOG(LOG_LV_ERR, "failed in create status of accessa");
			return 1;
		}
		*need_free_accessa_status = 1;
		*need_rewrite_accessa_status = 1;
	} else {
		old_accessa_status = (accessa_status_t *)buffer_data;
		// statusを取り出す。
		if (old_accessa_status->groups_data_size > 0 &&
		    lookup_accessa_status_find(
		    &accessa_status_group,
		    &accessa_status_record,
		    old_accessa_status,
		    lookup_record_roundrobin_cb_arg->name,
		    NULL)) {
			LOG(LOG_LV_ERR, "failed in find from status of accessa");
			return 1;
		}
		if (accessa_status_group == NULL) {
			// グループを追加する
			if (lookup_accessa_status_add_group(
			    &new_accessa_status,
			    old_accessa_status,
			    lookup_record_roundrobin_cb_arg->name,
			    NULL)) {
				LOG(LOG_LV_ERR, "failed in add group to status of accessa");
				return 1;
			}
			*need_free_accessa_status = 1;
			*need_rewrite_accessa_status = 1;
		} else {
			new_accessa_status = old_accessa_status;
			accessa_status_group->record_rr_idx
			    = (accessa_status_group->record_rr_idx + 1) % lookup_record_roundrobin_cb_arg->record_members_count;
			if (shared_buffer_set_dirty(lookup->accessa->accessa_buffer)) {
				LOG(LOG_LV_ERR, "failed in set dirty");
				return 1;
			}
		}
	}
	*accessa_status = new_accessa_status;
	// マッチする情報を引っ張り出す
	// マッチ情報にはsort_valueを付与しておく
	lookup_record_match_foreach_arg.record_rr_idx = accessa_status_group->record_rr_idx;
	if (bhash_foreach(
	    lookup_record_roundrobin_cb_arg->target,
	    lookup_record_match_foreach,
	    &lookup_record_match_foreach_arg))  {
		LOG(LOG_LV_ERR, "failed in foreach of bhash");
		return 1;
	}
	// マッチしたもののsort_valueを小さい順に並べる
	qsort(lookup->output.entry, lookup->output.entry_count, sizeof(lookup_output_entry_t), output_entry_cmp);
	// max_record分を超過しているものは無かったことにする
	if (lookup->output.entry_count > lookup_record_roundrobin_cb_arg->max_records) {
		lookup->output.entry_count = lookup_record_roundrobin_cb_arg->max_records;
	}

	return 0;
}
	
static int
lookup_record_roundrobin(
    lookup_t *lookup,
    int64_t max_records,
    int64_t record_members_count,
    bhash_t *target,
    const char *name,
    int64_t record_select_algorithm)
{
	lookup_record_roundrobin_cb_arg_t lookup_record_roundrobin_cb_arg = {
		.lookup = lookup,
		.max_records = max_records,
		.record_members_count = record_members_count,
		.target = target,
		.name = name,
		.record_select_algorithm = record_select_algorithm
	};

	ASSERT(lookup != NULL);
	ASSERT(max_records > 0);
	ASSERT(target != NULL);
	ASSERT(name != NULL);
        if (lookup_accessa_status_handle(lookup, lookup_record_roundrobin_cb, &lookup_record_roundrobin_cb_arg)) {
                LOG(LOG_LV_ERR, "failed in handling of accessa status");
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
	const char *cnt, *param;
	const char *bin_data;
	size_t bin_data_size;
	bhash_t target;

	ASSERT(lookup != NULL);
	ASSERT(group_itr != NULL);
	name = bson_iterator_key(group_itr);
	// レコード選択アルゴリズムを取得
	snprintf(path, sizeof(path), "%s.%s", name, "recordSelectAlgorithmValue");
	if (bson_helper_itr_get_long(group_itr, &record_select_algorithm, path, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get value of record select algorithm");
		return 1;
	}
	// lookupタイプによって、何のパラメータからデータを取り出すかが変わる
	switch (lookup->params->lookup_type) {
	case LOOKUP_TYPE_NATIVE_A:
		param = "ipv4Hostnames";
		cnt = "ipv4RecordMembersCount";
		break;
	case LOOKUP_TYPE_NATIVE_AAAA:
		param = "ipv6Hostnames";
		cnt = "ipv6RecordMembersCount";
		break;
	case LOOKUP_TYPE_NATIVE_PTR:
		switch (lookup->params->revaddr_mask.addr.family) {
		case AF_INET:
			param = "ipv4Addresses";
			cnt = "ipv4RecordMembersCount";
			break;
		case AF_INET6:
			param = "ipv6Addresses";
			cnt = "ipv6RecordMembersCount";
			break;
		default:
			LOG(LOG_LV_ERR, "unsupported address family");
			return 1;
		}
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected type of lookup");
		return 1;
	}
	// groupにターゲットとなるレコードが最大どのくらいいるか取得
	snprintf(path, sizeof(path), "%s.%s", name, cnt);
	if (bson_helper_itr_get_long(group_itr, &record_members_count, path, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get count of record Members");
		return 1;
	}
	// レスポンスで返す最大レコード数を取得 
	snprintf(path, sizeof(path), "%s.%s", name, "maxRecords");
	if (bson_helper_itr_get_long(group_itr, &max_records, path, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get max record");
		return 1;
	}
	// メンバより最大レコード数が多い場合、メンバの数に合わせる
	if (max_records > record_members_count) {
		max_records = record_members_count;
	}
	if (max_records <= 0) {
		/* no record */
		LOG(LOG_LV_INFO, "lookup dns record is empty (%s)", name);
		return 0;
	}
	// 対象タのハッシュデータ取り出し
	snprintf(path, sizeof(path), "%s.%s", name, param);
	if (bson_helper_itr_get_binary(group_itr, &bin_data, &bin_data_size, path, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get binary (%s)", path);
		return 1;
	}
	if (bhash_create_wrap_bhash_data(&target, bin_data, bin_data_size)) {
		LOG(LOG_LV_ERR, "failed in create of bhash");
		return 1;
	}
	// 各アルゴリズムの処理
	switch (record_select_algorithm) {
	case 0: /* random */
		if (lookup_record_basic(lookup, max_records, record_members_count, &target, record_select_algorithm)) {
			LOG(LOG_LV_ERR, "failed in lookup record by random");
			return 1;
		}
		break;
	case 1: /* priority */
		if (lookup_record_basic(lookup, max_records, record_members_count, &target, record_select_algorithm)) {
			LOG(LOG_LV_ERR, "failed in lookup record by priority");
			return 1;
		}
		break;
	case 2: /* roundrobin */
		if (lookup_record_roundrobin(lookup, max_records, record_members_count, &target, name, record_select_algorithm)) {
			LOG(LOG_LV_ERR, "failed in lookup record by roundrobin");
			return 1;
		}
		break;
	case 3: /* weight */
		/* XXX */
		break;
	default:
		/* NOTREACHED */
		ABORT("unsupported algorithm");
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
	// ランダムにインデックスを作成し
	idx = (int)(random() % (int)group_members_count);
	// そのインデックスにあるデータを引っ張る。なければエラーを返す。
	if (bson_helper_bson_get_itr_by_idx(group_itr, &lookup->params->status, "groups", idx)) {
		LOG(LOG_LV_ERR, "failed in get iterator of groups");
		return 1;
	}

	return 0;
}

static int
lookup_group_priority_foreach(
	void *foreach_arg,
	const char *path,
	bson_iterator *itr)
{
	lookup_group_priority_foreach_arg_t *lookup_group_priority_foreach_arg = foreach_arg;
	char p[MAX_BSON_PATH_LEN];
	int64_t priority;
	const char *name;

	ASSERT(foreach_arg != NULL);
	ASSERT(path != NULL);
	ASSERT(itr != NULL);
	name = bson_iterator_key(itr);
	snprintf(p, sizeof(p), "%s.%s", name, "priority");
        // priorityの値を取得する
	if (bson_helper_itr_get_long(itr, &priority, p, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in get value of priority (%s)", p);
		goto last;
	}
	// priorityが現在のmax_priorityより小さければそれを採用する
	// つまり、値が小さい方が優先
	if (priority < lookup_group_priority_foreach_arg->max_priority) {
		lookup_group_priority_foreach_arg->max_priority = priority;
		*lookup_group_priority_foreach_arg->group_itr = *itr;
	}
last:
	return BSON_HELPER_FOREACH_SUCCESS;
}

static int
lookup_group_priority(
	lookup_t *lookup,
	bson_iterator *group_itr)
{
	lookup_group_priority_foreach_arg_t lookup_group_priority_foreach_arg = {
		.max_priority = INITIAL_MAX_PRIORITY,
		.group_itr = group_itr,
	};
	ASSERT(lookup != NULL);
	ASSERT(group_itr != NULL);
	// bsonの中からpriorityが一番高いものを探す
	if (bson_helper_bson_foreach(
	    &lookup->params->status,
	    "groups",
	    lookup_group_priority_foreach,
	    &lookup_group_priority_foreach_arg)) {
		LOG(LOG_LV_ERR, "failed in get iterator of groups");
		return 1;
	}
	// groupが何も見つからなかったらエラーを返す
	if (lookup_group_priority_foreach_arg.max_priority == INITIAL_MAX_PRIORITY) {
		LOG(LOG_LV_ERR, "no group");
		return 1;
	}

	return 0;
}

static int
lookup_group_roundrobin_cb(
	lookup_t *lookup,
	void *handler_cb_arg,
	accessa_status_t **accessa_status,
	int *need_free_accessa_status,
        int *need_rewrite_accessa_status)
{
	lookup_group_roundrobin_cb_arg_t *lookup_group_roundrobin_cb_arg = handler_cb_arg;
	char *buffer_data = NULL;
	accessa_status_t *new_accessa_status = NULL;

	ASSERT(lookup != NULL);
	ASSERT(handler_cb_arg != NULL);
	ASSERT(accessa_status != NULL);
	ASSERT(need_free_accessa_status != NULL);
	// accessaのstatus情報を読み込む
	if (shared_buffer_read(lookup->accessa->accessa_buffer, &buffer_data, NULL)) {
		LOG(LOG_LV_ERR, "failed in read from accessa buffer");
		return 1;
	}
	if (buffer_data == NULL) {
		// データが無ければ新たに作る
		if (lookup_accessa_status_create(&new_accessa_status, NULL, NULL)) {
			LOG(LOG_LV_ERR, "dailes in create status of addessa");
			return 1;
		}
		*need_free_accessa_status = 1;
		*need_rewrite_accessa_status = 1;
	} else {
		new_accessa_status = (accessa_status_t *)buffer_data; 
		new_accessa_status->group_rr_idx
		     = (new_accessa_status->group_rr_idx + 1) % lookup_group_roundrobin_cb_arg->group_members_count;
		// 値が変わったのでdirtyをセットしておいて後から更新されるようにする
		if (shared_buffer_set_dirty(lookup->accessa->accessa_buffer)) {
			LOG(LOG_LV_ERR, "failed in set dirty");
			return 1;
		}
	}
	*accessa_status = new_accessa_status;
	if (bson_helper_bson_get_itr_by_idx(
	    lookup_group_roundrobin_cb_arg->group_itr,
	    &lookup->params->status,
	    "groups",
	    new_accessa_status->group_rr_idx)) {
		LOG(LOG_LV_ERR, "failed in get iterator of groups");
		return 1;
	}

	return 0;
}

static int
lookup_group_roundrobin(
	lookup_t *lookup,
	bson_iterator *group_itr,
	int64_t group_members_count)
{
	lookup_group_roundrobin_cb_arg_t lookup_group_roundrobin_cb_arg = {
		.group_itr = group_itr,
		.group_members_count = group_members_count,
	};

	ASSERT(lookup != NULL);
	ASSERT(group_itr != NULL);
	ASSERT(group_members_count > 0);
	// 過去のaccessaのstatus情報をみながら、採用を決定する
	if (lookup_accessa_status_handle(lookup, lookup_group_roundrobin_cb, &lookup_group_roundrobin_cb_arg)) {
		LOG(LOG_LV_ERR, "failed in handling of accessa status");
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
	// アルゴリズム情報を取得
	if (bson_helper_bson_get_long(&lookup->params->status, &group_select_algorithm, "groupSelectAlgorithmValue", NULL)) {
		LOG(LOG_LV_ERR, "failed in get value of group select algorithm value");
		return 1;
	}
	// グループの最大数を取得
	if (bson_helper_bson_get_long(&lookup->params->status, &group_members_count, "groupMembersCount", NULL)) {
		LOG(LOG_LV_ERR, "failed in get value of group members count");
		return 1;
	}
	// 各アルゴリズムの処理
	switch (group_select_algorithm) {
	case 0: /* random */
		if (lookup_group_random(lookup, &group_itr, group_members_count)) {
			LOG(LOG_LV_ERR, "failed in lookup group by random");
			return 1;
		}
		break;
	case 1: /* priority */
		if (lookup_group_priority(lookup, &group_itr)) {
			LOG(LOG_LV_ERR, "failed in lookup group by priority");
			return 1;
		}
		break;
	case 2: /* roundrobin */
		if (lookup_group_roundrobin(lookup, &group_itr, group_members_count)) {
			LOG(LOG_LV_ERR, "failed in lookup group by roundrobin");
			return 1;
		}
		break;
	case 3: /* weight */
		/* XXX */
		break;
	default:
		/* NOREACHED */
		ABORT("unexpected algorithm of group select");
		return 1;
	}
	if (lookup_record(lookup, &group_itr)) {
		LOG(LOG_LV_ERR, "failed in lookup record");
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
	// group選択のオーダー設定を取得
	if (bson_helper_bson_get_long(&lookup->params->status, &group_select_order, "groupSelectOrderValue", NULL)) {
		LOG(LOG_LV_ERR, "failed in get value of group select order");
		return 1;
	}
	// レコードのタイプを判定しておく
	if (strcasecmp(lookup->input.type, "A") == 0) {
		lookup->params->lookup_type = LOOKUP_TYPE_NATIVE_A;
	} else if (strcasecmp(lookup->input.type, "AAAA") == 0) {
		lookup->params->lookup_type = LOOKUP_TYPE_NATIVE_AAAA;
	} else if (strcmp(lookup->input.type, "PTR") == 0){
		lookup->params->lookup_type = LOOKUP_TYPE_NATIVE_PTR;
	} else if (strcmp(lookup->input.type, "NS") == 0){
		/* XXX ns record */
		LOG(LOG_LV_DEBUG, "ns record is unsupported");
		return 1;
	} else {
		/* log */
		LOG(LOG_LV_ERR, "unexpected type (%s)", lookup->input.type);
		return 1;
	}
       	// PTRレコードの場合アドレスを検索しやすい形に変換しておく
	if (lookup->params->lookup_type == LOOKUP_TYPE_NATIVE_PTR) {
		// 自前sockaddr構造体に変換
		if (revaddrstr_to_addrmask(&lookup->params->revaddr_mask, &lookup->params->revfmt_type, lookup->input.name)) {
			LOG(LOG_LV_ERR, "failed in convert address and mask");
			return 1;
		}
		// 文字列に変換
		if (inet_ntop(
		    lookup->params->revaddr_mask.addr.family,
		    &lookup->params->revaddr_mask.addr.in_addr,
		    lookup->params->revaddr_str,
		    sizeof(lookup->params->revaddr_str)) == NULL) {
			LOG(LOG_LV_ERR, "failed in convert address");
			return 1;
		}
	}
	// 最初にgroupを決定する
	if (group_select_order == 0) { 
		// domainMapをチェック
	  	if (lookup_domain_map(lookup, &group, &group_itr)) {
			LOG(LOG_LV_ERR, "failed in get value of group select order");
			return 1;
		}
		if (!group) {
			// remoteAddressMapをチェック
			if (lookup_remote_address_map(lookup, &group, &group_itr)) {
				LOG(LOG_LV_ERR, "failed in lookup of remote address");
				return 1;
			}
		}
	} else {
		// remoteAddrssMapをチェック
		if (lookup_remote_address_map(lookup, &group, &group_itr)) {
			LOG(LOG_LV_ERR, "failed in lookup of remote address");
			return 1;
		}
		if (!group) {
			// domainMapをチェック
			if (lookup_domain_map(lookup, &group, &group_itr)) {
				LOG(LOG_LV_ERR, "failed in get value of group select order");
				return 1;
			}
		}
	}
	if (group) {
		// groupが見つかったので、レコードを探す
		if (lookup_record(lookup, &group_itr)) {
			LOG(LOG_LV_ERR, "failed in lookup record");
			return 1;
		}
	} else {
		// groupが見つかってないので、アルゴリズムからグループを決定する
		if (lookup_group(lookup)) {
			LOG(LOG_LV_ERR, "failed in lookup group");
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
