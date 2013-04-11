#ifndef BSON_HELPER
#define BSON_HELPER

#include "bson/bson.h"

#ifndef MAX_BSON_PATH_LEN
#define MAX_BSON_PATH_LEN 2046
#endif

#define BSON_HELPER_FOREACH_SUCCESS 0
#define BSON_HELPER_FOREACH_ERROR 1 

int bson_helper_itr_get_itr(
    bson_iterator *dst_itr,
    bson_iterator *src_itr,
    const char *path);

int bson_helper_itr_get_itr_by_idx(
    bson_iterator *dst_itr,
    bson_iterator *src_itr,
    const char *path,
    int target_idx);

int bson_helper_bson_get_itr(
    bson_iterator *dst_itr,
    bson *bson,
    const char *path);

int bson_helper_bson_get_itr_by_idx(
    bson_iterator *dst_itr,
    bson *bson,
    const char *path,
    int target_idx);

int bson_helper_itr_foreach(
    bson_iterator *start_itr,
    const char *path,
    int (*foreach_cb)(void * foreach_arg, const char *path, bson_iterator *itr),
    void *foreach_cb_arg);

int bson_helper_itr_get_len(
    bson_iterator *start_itr,
    const char *path,
    int *member_count);

int bson_helper_bson_foreach(
    bson *bson,
    const char *path,
    int (*foreach_cb)(void * foreach_arg, const char *path, bson_iterator *itr),
    void *foreach_cb_arg);

int bson_helper_bson_get_len(
    bson *bson,
    const char *path,
    int *members_count);

int bson_helper_bson_get_string(
    bson *bson,
    char const **s,
    const char *path,
    const char *default_path);

int bson_helper_bson_get_bool(
    bson *bson,
    int *b,
    const char *path,
    const char *default_path);

int bson_helper_bson_get_long(
    bson *bson,
    int64_t *l,
    const char *path,
    const char *default_path);

int bson_helper_bson_get_binary(
    bson *bson,
    char const **data,
    size_t *data_size,
    const char *path,
    const char *default_path);

int bson_helper_itr_get_string(
    bson_iterator *src_itr,
    char const **s,
    const char *path,
    bson *bson,
    const char *default_path);

int bson_helper_itr_get_bool(
    bson_iterator *src_itr,
    int *b,
    const char *path,
    bson *bson,
    const char *default_path);

int bson_helper_itr_get_long(
    bson_iterator *src_itr,
    int64_t *l,
    const char *path,
    bson *bson,
    const char *default_path);

int bson_helper_itr_get_binary(
    bson_iterator *src_itr,
    char const **data,
    size_t *data_size,
    const char *path,
    bson *bson,
    const char *default_path);

int bson_helper_bson_copy_string(
    bson *dst_bson,
    bson *src_bson,
    const char *path,
    const char *default_path);

int bson_helper_bson_copy_bool(
    bson *dst_bson,
    bson *src_bson,
    const char *path,
    const char *default_path);

int bson_helper_bson_copy_long(
    bson *dst_bson,
    bson *src_bson,
    const char *path,
    const char *default_path);


#endif
