#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bson/bson.h"

#include "common_macro.h"
#include "bson_helper.h"
#include "logger.h"

#define SET_NULL_ITERATOR(itr) ((itr)->cur = NULL)
#define IS_NULL_ITERATOR(itr) ((itr)->cur == NULL)

static int bson_helper_itr_get_value(
    bson_type bson_type,
    char const **s,
    int *b,
    int64_t *l,
    char const **data,
    size_t *data_size,
    bson_iterator *itr,
    int itr_cnt);
static int bson_helper_bson_copy_base(
    bson *dst_bson,
    bson *src_bson,
    bson_type bson_type,
    const char *path,
    const char *default_path);
static int bson_helper_itr_loop_base(
    bson_iterator *start_itr,
    const char *path,
    int (*foreach_cb)(void *foreach_arg, const char *path, bson_iterator *itr),
    void *foreach_cb_arg,
    int *member_count,
    bson_iterator *dst_itr,
    int target_idx);

static int
bson_helper_itr_get_value(
    bson_type arg_bson_type,
    char const **s,
    int *b,
    int64_t *l,
    char const **data,
    size_t *data_size,
    bson_iterator *itr,
    int itr_cnt)
{
	int i;
	bson_type itr_bson_type;

	ASSERT(itr != NULL);
	ASSERT(itr_cnt > 0);
	switch (arg_bson_type) {
	case BSON_STRING:
		ASSERT(s != NULL);
		break;
	case BSON_BOOL:
		ASSERT(b != NULL);
		break;
	case BSON_LONG:
		ASSERT(l != NULL);
		break;
	case BSON_BINDATA:
		ASSERT(data != NULL);
		ASSERT(data_size != NULL);
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected bson type");
		return 1;
	}
	for (i = 0; i < itr_cnt; i++) {
		if (IS_NULL_ITERATOR(&itr[i])) {
			continue;
		}
		itr_bson_type = bson_iterator_type(&itr[i]);
		switch (itr_bson_type) {
		case BSON_STRING:
			if (arg_bson_type != BSON_STRING) {
				LOG(LOG_LV_DEBUG, "bson type is mismatch (itr = %d, arg = %d)", itr_bson_type, arg_bson_type);
				break;
			}
			*s = bson_iterator_string(&itr[i]);
			return 0;
		case BSON_BOOL:
			if (arg_bson_type != BSON_BOOL) {
				LOG(LOG_LV_DEBUG, "bson type is  mismatch (itr = %d, arg = %d)", itr_bson_type, arg_bson_type);
				break;
			}
			*b =  bson_iterator_bool(&itr[i]);
			return 0;
		case BSON_LONG:
			if (arg_bson_type != BSON_LONG) {
				LOG(LOG_LV_DEBUG, "bson type is mismatch (itr = %d, arg = %d)", itr_bson_type, arg_bson_type);
				break;
			}
			*l =  bson_iterator_long(&itr[i]);
			return 0;
		case BSON_BINDATA:
			if (arg_bson_type != BSON_BINDATA) {
				LOG(LOG_LV_DEBUG, "bson type is mismatch (itr = %d, arg = %d)", itr_bson_type, arg_bson_type);
				break;
			}
			*data =  bson_iterator_bin_data(&itr[i]);
			*data_size =  (size_t)bson_iterator_bin_len(&itr[i]);
			return 0;
		case BSON_EOO:
			/* not found */
			break;
		default:
			/* NOTREACHED */
			LOG(LOG_LV_DEBUG, "unexpected bson type (loop = %d, type = %d)", i, arg_bson_type);
			ABORT("unexpected bson type");
			return 1;
		}
	}

	return 1;
}

static int
bson_helper_bson_copy_base(
    bson *dst_bson,
    bson *src_bson,
    bson_type bson_type,
    const char *path,
    const char *default_path)
{
	char const *s;
	int b;
	int64_t l;

	ASSERT(dst_bson !=NULL);
	ASSERT(src_bson !=NULL);
	ASSERT(path !=NULL);

	switch (bson_type) {
	case BSON_STRING:
		if (bson_helper_bson_get_string(
		    src_bson,
		    &s,
		    path,
		    default_path)) {
		    return 1;
		}
		bson_append_string(dst_bson, path, s);
		break;
	case BSON_BOOL:
		if (bson_helper_bson_get_bool(
		    src_bson,
		    &b,
		    path,
		    default_path)) {
		    return 1;
		}
		bson_append_bool(dst_bson, path, b);
		break;
	case BSON_LONG:
		if (bson_helper_bson_get_long(
		    src_bson,
		    &l,
		    path,
		    default_path)) {
		    return 1;
		}
		bson_append_long(dst_bson, path, l);
		break;
	default:
		errno = EINVAL;
		return 1;
	}

	return 0;
}

static int
bson_helper_itr_loop_base(
    bson_iterator *start_itr,
    const char *path,
    int (*foreach_cb)(void *foreach_arg, const char *path, bson_iterator *itr),
    void *foreach_cb_arg,
    int *member_count,
    bson_iterator *dst_itr,
    int target_idx)
{
	int result = 1;
	bson_iterator itr, sub_itr;
	bson_type bson_type;
	char *copy_path, *start_ptr, *end_ptr;
	int found;
	int last = 0;
	int count = 0;

	if (start_itr == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	itr = *start_itr;
	if (strcmp(path, ".") == 0) {
		result = 0;
		goto current_path;
	}
	copy_path = strdup(path);
	if (copy_path == NULL) {
		// logger
		return result;
	}
	start_ptr = copy_path;
	while (1) {
		end_ptr = strchr(start_ptr, '.');
		if (end_ptr == NULL) {
			last = 1;
		} else {
			*end_ptr = '\0';
		}
		found = 0;
		while (1) {
			if (itr.first) {
				if (!bson_iterator_next(&itr)) {
					break;
				}
			}
			if (strcmp(start_ptr, bson_iterator_key(&itr)) == 0) {
				found = 1;
				break;
			}
	 		if (!bson_iterator_next(&itr)) {
				break;
			}
		}
		if (!found) {
			break;
		}
		if (last) {
			result = 0;
			break;
		}
		bson_type = bson_iterator_type(&itr);
		if (bson_type != BSON_OBJECT && bson_type != BSON_ARRAY) {
			break;
		}
		bson_iterator_subiterator(&itr, &sub_itr);
		itr = sub_itr;
		start_ptr = end_ptr + 1;
	}
	free(copy_path);
	if (found) {
current_path:
		bson_iterator_subiterator(&itr, &sub_itr);
		while (bson_iterator_next(&sub_itr)) {
			if (target_idx != -1) {
				if (target_idx == count) {
					*dst_itr = sub_itr;
					return 0;
				}
			}
			if (foreach_cb) {
				if (foreach_cb(foreach_cb_arg, path, &sub_itr) != BSON_HELPER_FOREACH_SUCCESS) {
					LOG(LOG_LV_DEBUG, "failed in foreach callback");
					return 1;
				}
			}
			count++;
		}
		if (target_idx != -1) {
			return 1;
		}
	}
	if (member_count) {
		*member_count = count;
	}

	return result;
}

int
bson_helper_itr_get_itr(
    bson_iterator *dst_itr,
    bson_iterator *src_itr,
    const char *path)
{
	int result = 1;
	bson_iterator sub_itr;
	bson_type bson_type;
	char *copy_path, *start_ptr, *end_ptr;
	int found;
	int last = 0;

	if (dst_itr == NULL ||
            src_itr == NULL ||
            path == NULL) {
		errno = EINVAL;
		return 1;
	}
	*dst_itr = *src_itr; 
	if (strcmp(path, ".") == 0) {
		result = 0;
		goto current_path;
	}
	copy_path = strdup(path);
	if (copy_path == NULL) {
		// logger
		return result;
	}
	start_ptr = copy_path;
	while (1) {
		end_ptr = strchr(start_ptr, '.');
		if (end_ptr == NULL) {
			last = 1;
		} else {
			*end_ptr = '\0';
		}
		found = 0;
		while (1) {
			if (dst_itr->first) {
				if (!bson_iterator_next(dst_itr)) {
					break;
				}
			}
			if (strcmp(start_ptr, bson_iterator_key(dst_itr)) == 0) {
				found = 1;
				break;
			}
			if (!bson_iterator_next(dst_itr)) {
				break;
			}
		}
		if (!found) {
			break;
		}
		if (last) {
			result = 0;
			break;
		}
		bson_type = bson_iterator_type(dst_itr);
		if (bson_type != BSON_OBJECT && bson_type != BSON_ARRAY) {
			break;
		}
		bson_iterator_subiterator(dst_itr, &sub_itr);
		*dst_itr = sub_itr;
		start_ptr = end_ptr + 1;
	}
	free(copy_path);

current_path:

	return result;
}

int
bson_helper_itr_get_itr_by_idx(
    bson_iterator *dst_itr,
    bson_iterator *start_itr,
    const char *path,
    int target_idx)
{
	if (start_itr == NULL ||
	    path == NULL ||
	    dst_itr == NULL ||
	    target_idx < 0) {
		errno = EINVAL;
		return 1;
	}
	return bson_helper_itr_loop_base(
	    start_itr,
	    path,
	    NULL,
	    NULL,
	    NULL,
            dst_itr,
            target_idx);
}

int
bson_helper_bson_get_itr(
    bson_iterator *dst_itr,
    bson *bson,
    const char *path)
{
	bson_iterator src_itr;

	if (bson == NULL) {
		return 1;
	}
	bson_iterator_init(&src_itr, bson);
	return bson_helper_itr_get_itr(
	    dst_itr,
	    &src_itr,
	    path);
}

int
bson_helper_bson_get_itr_by_idx(
    bson_iterator *dst_itr,
    bson *bson,
    const char *path,
    int target_idx)
{
	bson_iterator src_itr;

	if (bson == NULL) {
		return 1;
	}
	bson_iterator_init(&src_itr, bson);
	return bson_helper_itr_get_itr_by_idx(
	    dst_itr,
	    &src_itr,
	    path,
	    target_idx);
}

int
bson_helper_itr_foreach(
    bson_iterator *start_itr,
    const char *path,
    int (*foreach_cb)(void *foreach_arg, const char *path, bson_iterator *itr),
    void *foreach_cb_arg)
{
	if (start_itr == NULL ||
	    path == NULL ||
	    foreach_cb == NULL) {
		errno = EINVAL;
		return 1;
	}
	return bson_helper_itr_loop_base(
	    start_itr,
	    path,
	    foreach_cb,
	    foreach_cb_arg,
	    NULL,
            NULL,
            -1);
}

int
bson_helper_itr_get_len(
    bson_iterator *start_itr,
    const char *path,
    int *member_count)
{
	if (start_itr == NULL ||
	    path == NULL ||
	    member_count == NULL) {
		errno = EINVAL;
		return 1;
	}
	return bson_helper_itr_loop_base(
	    start_itr,
	    path,
	    NULL,
	    NULL,
	    member_count,
            NULL,
            -1);
}

int
bson_helper_bson_foreach(
    bson *bson,
    const char *path,
    int (*foreach_cb)(void *foreach_arg, const char *path, bson_iterator *itr),
    void *foreach_cb_arg)
{
	bson_iterator itr;

	if (bson == NULL) {
		return 1;
	}
	bson_iterator_init(&itr, bson);
	return bson_helper_itr_foreach(
    	    &itr,
    	    path,
    	    foreach_cb,
	    foreach_cb_arg);
}

int
bson_helper_bson_get_len(
    bson *bson,
    const char *path,
    int *members_count)
{
	bson_iterator itr;

	if (bson == NULL) {
		return 1;
	}
	bson_iterator_init(&itr, bson);
	return bson_helper_itr_get_len(
    	    &itr,
    	    path,
    	    members_count);
}

int
bson_helper_bson_get_string(
    bson *bson,
    char const **s,
    const char *path,
    const char *default_path)
{
	bson_iterator itr[2];

	if (bson == NULL ||
            s == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	SET_NULL_ITERATOR(&itr[0]);
	SET_NULL_ITERATOR(&itr[1]);
	bson_helper_bson_get_itr(&itr[0], bson, path);
	if (default_path != NULL) {
		bson_helper_bson_get_itr(&itr[1], bson, default_path);
	}
        return bson_helper_itr_get_value(
            BSON_STRING,
            s,
            NULL,
            NULL,
	    NULL,
	    NULL,
            itr,
            2);
}

int
bson_helper_bson_get_bool(
    bson *bson,
    int *b,
    const char *path,
    const char *default_path)
{
	bson_iterator itr[2];

	if (bson == NULL ||
            b == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	SET_NULL_ITERATOR(&itr[0]);
	SET_NULL_ITERATOR(&itr[1]);
	bson_helper_bson_get_itr(&itr[0], bson, path);
	if (default_path != NULL) {
		bson_helper_bson_get_itr(&itr[1], bson, default_path);
	}
        return bson_helper_itr_get_value(
            BSON_BOOL,
            NULL,
            b,
            NULL,
            NULL,
            NULL,
            itr,
            2);
}

int
bson_helper_bson_get_long(
    bson *bson,
    int64_t *l,
    const char *path,
    const char *default_path)
{
	bson_iterator itr[2];

	if (bson == NULL ||
            l == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	SET_NULL_ITERATOR(&itr[0]);
	SET_NULL_ITERATOR(&itr[1]);
	bson_helper_bson_get_itr(&itr[0], bson, path);
	if (default_path != NULL) {
		bson_helper_bson_get_itr(&itr[1], bson, default_path);
	}
        return bson_helper_itr_get_value(
            BSON_LONG,
            NULL,
            NULL,
            l,
            NULL,
            NULL,
            itr,
            2);
}

int
bson_helper_bson_get_binary(
    bson *bson,
    char const **data,
    size_t *data_size,
    const char *path,
    const char *default_path)
{
	bson_iterator itr[2];

	if (bson == NULL ||
            data == NULL ||
            data_size == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	SET_NULL_ITERATOR(&itr[0]);
	SET_NULL_ITERATOR(&itr[1]);
	bson_helper_bson_get_itr(&itr[0], bson, path);
	if (default_path != NULL) {
		bson_helper_bson_get_itr(&itr[1], bson, default_path);
	}
        return bson_helper_itr_get_value(
            BSON_BINDATA,
            NULL,
            NULL,
            NULL,
	    data,
	    data_size,
            itr,
            2);
}

int
bson_helper_itr_get_string(
    bson_iterator *src_itr,
    char const **s,
    const char *path,
    bson *bson,
    const char *default_path)
{
	bson_iterator dst_itr;
	int result;
	
	if (src_itr == NULL ||
            s == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	bson_helper_itr_get_itr(&dst_itr, src_itr, path);
        result = bson_helper_itr_get_value(
            BSON_STRING,
            s,
            NULL,
            NULL,
            NULL,
            NULL,
            &dst_itr,
            1);
	if (!(result && default_path != NULL && bson != NULL)) {
		return result;
	}
	return bson_helper_bson_get_string(
    	    bson,
    	    s,
    	    default_path,
	    NULL);
}

int
bson_helper_itr_get_bool(
    bson_iterator *src_itr,
    int *b,
    const char *path,
    bson *bson,
    const char *default_path)
{
	bson_iterator dst_itr;
	int result;

	if (src_itr == NULL ||
            b == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	bson_helper_itr_get_itr(&dst_itr, src_itr, path);
        result = bson_helper_itr_get_value(
            BSON_BOOL,
            NULL,
            b,
            NULL,
            NULL,
            NULL,
            &dst_itr,
            1);
	if (!(result && default_path != NULL && bson != NULL)) {
		return result;
	}
	return bson_helper_bson_get_bool(
    	    bson,
    	    b,
    	    default_path,
	    NULL);
}

int
bson_helper_itr_get_long(
    bson_iterator *src_itr,
    int64_t *l,
    const char *path,
    bson *bson,
    const char *default_path)
{
	bson_iterator dst_itr;
	int result;

	if (src_itr == NULL ||
            l == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	bson_helper_itr_get_itr(&dst_itr, src_itr, path);
        result = bson_helper_itr_get_value(
            BSON_LONG,
            NULL,
            NULL,
            l,
            NULL,
            NULL,
            &dst_itr,
            1);
	if (!(result && default_path != NULL && bson != NULL)) {
		return result;
	}
	return bson_helper_bson_get_long(
    	    bson,
    	    l,
    	    default_path,
	    NULL);
}

int
bson_helper_itr_get_binary(
    bson_iterator *src_itr,
    char const **data,
    size_t *data_size,
    const char *path,
    bson *bson,
    const char *default_path)
{
	bson_iterator dst_itr;
	int result;

	if (src_itr == NULL ||
            data == NULL ||
            data_size == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
	bson_helper_itr_get_itr(&dst_itr, src_itr, path);
        result = bson_helper_itr_get_value(
            BSON_BINDATA,
            NULL,
            NULL,
            NULL,
            data,
            data_size,
            &dst_itr,
            1);
	if (!(result && default_path != NULL && bson != NULL)) {
		return result;
	}
	return bson_helper_bson_get_binary(
    	    bson,
    	    data,
            data_size,
    	    default_path,
	    NULL);
}

int
bson_helper_bson_copy_string(
    bson *dst_bson,
    bson *src_bson,
    const char *path,
    const char *default_path)
{
	if (dst_bson == NULL ||
	    src_bson == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
        return bson_helper_bson_copy_base(
            dst_bson,
            src_bson,
            BSON_STRING,
            path,
            default_path);
}

int
bson_helper_bson_copy_bool(
    bson *dst_bson,
    bson *src_bson,
    const char *path,
    const char *default_path)
{
	if (dst_bson == NULL ||
	    src_bson == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
        return bson_helper_bson_copy_base(
            dst_bson,
            src_bson,
            BSON_BOOL,
            path,
            default_path);
}

int
bson_helper_bson_copy_long(
    bson *dst_bson,
    bson *src_bson,
    const char *path,
    const char *default_path)
{
	if (dst_bson == NULL ||
	    src_bson == NULL ||
	    path == NULL) {
		errno = EINVAL;
		return 1;
	}
        return bson_helper_bson_copy_base(
            dst_bson,
            src_bson,
            BSON_LONG,
            path,
            default_path);
}
