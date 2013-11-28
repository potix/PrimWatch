#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>

#include "common_macro.h"
#include "bhash.h"

#define DEFAULT_BUFFER_SIZE (4 * 1024)
#define MAGIC 0xDEADBEEFCAFEBABEULL

typedef enum bhash_method_flag bhash_method_flag_t;
typedef struct bhash_hash_table_entry bhash_hash_table_entry_t;

enum bhash_method_flag {
	METHOD_FLAG_PUT = 1,
	METHOD_FLAG_REPLACE,
	METHOD_FLAG_APPEND,
	METHOD_FLAG_GET,
	METHOD_FLAG_GET_ITERATOR
};

struct bhash_kv_entry {
	off_t next_kv_entry;
	off_t next_free_kv_entry;
	size_t key_actual_size;
	size_t key_align_size;
	size_t value_actual_size;
	size_t value_align_size;
	uint64_t padding;
	char key_value_start[0];
};

struct bhash_hash_table_entry {
	off_t kv_entry_start;
	uint64_t padding;
	char key_value_entry_start[0];
};

struct bhash_data {
        size_t data_size;
	int hash_size;
	int total_kv_entry_count;
        int free_kv_entry_count;
        off_t free_kv_entry_start;
        off_t last_kv_entry_end;
	uint64_t padding;
	char hash_table_start[0];
};

#define ALIGN_SIZE(size) ((size) + 8 - ((size) & 7))
#define KV_ENTRY_SIZE(key_align_size, value_align_size) (sizeof(bhash_kv_entry_t) + (key_align_size) + (value_align_size))

#define HASH_TABLE_START_OFFSET (offsetof(bhash_data_t, hash_table_start))
#define KV_ENTRY_AREA_OFFSET(bhash_data) (HASH_TABLE_START_OFFSET + ((bhash_data)->hash_size * sizeof(bhash_hash_table_entry_t)))
#define FREE_KV_ENTRY_AREA_OFFSET(bhash_data) KV_ENTRY_AREA_OFFSET(bhash_data)
#define HASH_KV_ENTRY_START_OFFSET(hash_table_entry) ((hash_table_entry)->kv_entry_start)
#define KEY_START_OFFSET (offsetof(bhash_kv_entry_t, key_value_start))
#define VALUE_START_OFFSET(kv_entry) (KEY_START_OFFSET + (kv_entry)->key_align_size)
#define NEXT_KV_ENTRY_OFFSET(kv_entry) ((kv_entry)->next_kv_entry)
#define NEXT_FREE_KV_ENTRY_OFFSET(kv_entry) ((kv_entry)->next_free_kv_entry)
#define FREE_KV_ENTRY_START_OFFSET(bhash_data) ((bhash_data)->free_kv_entry_start)
#define LAST_KV_ENTRY_END_OFFSET(bhash_data) ((bhash_data)->last_kv_entry_end)

#define END_PTR(bhash_data) (((char *)(bhash_data)) + (bhash_data)->data_size)
#define HASH_TABLE_START_PTR(bhash_data) (bhash_hash_table_entry_t *)(((char *)(bhash_data)) + HASH_TABLE_START_OFFSET);
#define KV_ENTRY_AREA_PTR(bhash_data) (bhash_kv_entry_t *)(((char *)(bhash_data)) + KV_ENTRY_AREA_OFFSET((bhash_data)))
#define FREE_KV_ENTRY_AREA_PTR(bhash_data) KV_ENTRY_AREA_PTR(bhash_data)
#define HASH_KV_ENTRY_START_PTR(hash_table_entry) (bhash_kv_entry_t *)(((char *)(bhash_data)) + HASH_KV_ENTRY_START_OFFSET(hash_table_entry))
#define	KEY_START_PTR(kv_entry) (char *)(((char *)(kv_entry)) + KEY_START_OFFSET)
#define	VALUE_START_PTR(kv_entry) (char *)(((char *)(kv_entry)) + VALUE_START_OFFSET((kv_entry)))
#define NEXT_KV_ENTRY_PTR(kv_entry) (bhash_kv_entry_t *)(((char *)(bhash_data)) + NEXT_KV_ENTRY_OFFSET(kv_entry))
#define NEXT_FREE_KV_ENTRY_PTR(kv_entry) (bhash_kv_entry_t *)(((char *)(bhash_data)) + NEXT_FREE_KV_ENTRY_OFFSET(kv_entry))
#define FREE_KV_ENTRY_START_PTR(kv_entry) (bhash_kv_entry_t *)(((char *)(bhash_data)) + FREE_KV_ENTRY_START_OFFSET((bhash_data)))
#define LAST_KV_ENTRY_END_PTR(bhash_data)  (bhash_kv_entry_t *)(((char *)(bhash_data)) + LAST_KV_ENTRY_END_OFFSET((bhash_data)))

#define KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, kv_entry) (((char *)(kv_entry)) - ((char *)(bhash_data)))

static int bhash_glow_buffer(
    bhash_t *bhash,
    size_t key_align_size,
    size_t value_align_size);
static int bhash_compute_value(
    const char *key,
    size_t key_size,
    int hash_size);
static int bhash_get_base(
    bhash_t *bhash,
    char **value,
    size_t *value_size,
    bhash_iterator_t *iterator,
    const char *key,
    size_t key_size,
    bhash_method_flag_t method_flag);
static int bhash_put_base(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size,
    bhash_method_flag_t method_flag,
    void (*replace_cb)(
        void *replace_cb_arg,
        const char *key,
        size_t key_size,
        char *old_value,
        size_t old_value_size,
        char *new_value,
        size_t new_value_size),
    void *replace_cb_arg);

static int
bhash_glow_buffer(
    bhash_t *bhash,
    size_t key_align_size,
    size_t value_align_size)
{
	bhash_data_t *bhash_data = bhash->bhash_data;
	bhash_data_t *new_bhash_data;
	size_t need_size = LAST_KV_ENTRY_END_OFFSET(bhash_data) + KV_ENTRY_SIZE(key_align_size, value_align_size);
	size_t new_size;
 
	if (bhash_data->data_size >= need_size) {
		return 0;
	}
	new_size = (need_size > bhash_data->data_size * 2) ? need_size * 2 : bhash_data->data_size * 2;
	new_bhash_data = realloc(bhash->bhash_data, new_size);
	if (new_bhash_data == NULL) {
		return 1;
	}
	bhash->bhash_data = new_bhash_data;
	bhash->bhash_data->data_size = new_size;

	return 0;
}

static int
bhash_compute_value(
    const char *key,
    size_t key_size,
    int hash_size)
{
	size_t i;
	uint64_t value;

	ASSERT(key != NULL);
	ASSERT(key_size > 0);
	ASSERT(hash_size > 0);
	if (hash_size == 1) {
		return 0;
	}
	value = key_size;
	for (i = 0; i < key_size; i++) {
		value = ((value << 5)  - 1) + key[i];
	}

	return (int)(value % (uint64_t)hash_size);
}

int
bhash_create(
    bhash_t **bhash,
    int hash_size,
    void (*free_cb)(
        void *free_cb_arg,
        char *key,
        size_t key_size,
        char *value,
        size_t value_size),
    void *free_cb_arg)
{
	int i;
	bhash_t *new = NULL;
	bhash_data_t *new_bhash_data = NULL;
	bhash_hash_table_entry_t *hash_table_entry;
	size_t new_bhash_data_size;

	if (bhash == NULL ||
	    hash_size < 1) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(bhash_t));
	if (new == NULL) {
		goto fail;
	}
	new_bhash_data_size = sizeof(bhash_data_t) + (hash_size * sizeof(bhash_hash_table_entry_t)) + DEFAULT_BUFFER_SIZE;
	new_bhash_data = malloc(new_bhash_data_size);
	if (new_bhash_data == NULL) {
		goto fail;
	}
	new_bhash_data->data_size = new_bhash_data_size;
	new_bhash_data->hash_size = hash_size;
	new_bhash_data->total_kv_entry_count = 0;
	new_bhash_data->free_kv_entry_count = 0;
	new_bhash_data->free_kv_entry_start = 0;
	new_bhash_data->last_kv_entry_end = KV_ENTRY_AREA_OFFSET(new_bhash_data);
	new_bhash_data->padding = MAGIC;
	hash_table_entry = HASH_TABLE_START_PTR(new_bhash_data);
	for (i = 0; i < hash_size; i++) {
		hash_table_entry->kv_entry_start = 0;
		hash_table_entry->padding = MAGIC;
		hash_table_entry++;	
	}
	new->free_cb = free_cb;
	new->free_cb_arg = free_cb_arg;
	new->bhash_data = new_bhash_data;
	new->wrap = 0;
	*bhash = new;
	
	return 0;

fail:
	free(new_bhash_data);
	free(new);

	return 1;
}

int
bhash_create_wrap_bhash_data(
    bhash_t *bhash,
    const char *bhash_data,
    size_t bhash_data_size)
{
	if (bhash == NULL ||
	    bhash_data == NULL ||
	    bhash_data_size < 1 ||
            ((bhash_data_t *)bhash_data)->data_size != bhash_data_size) {
		errno = EINVAL;
		return 1;
	}
	ASSERT(((bhash_data_t *)bhash_data)->padding == MAGIC);
	bhash->free_cb = NULL;
	bhash->free_cb_arg = NULL;
	bhash->bhash_data = (bhash_data_t *)bhash_data;
	bhash->wrap = 1;

	return 0;
}

int
bhash_clone(
    bhash_t **bhash,
    const char *bhash_data)
{
	bhash_t *new = NULL;
	bhash_data_t *clone_data = NULL;

	if (bhash == NULL ||
	    bhash_data == NULL ||
            ((bhash_data_t *)bhash_data)->data_size <= sizeof(bhash_data_t)) {
		errno = EINVAL;
		return 1;
	}
	ASSERT(((bhash_data_t *)bhash_data)->padding == MAGIC);
	new = malloc(sizeof(bhash_t));
	if (new == NULL) {
		goto fail;
	}
	clone_data = malloc(((bhash_data_t *)bhash_data)->data_size);
	if (clone_data == NULL) {
		goto fail;
	}
	memcpy(clone_data, bhash_data, ((bhash_data_t *)bhash_data)->data_size);
	new->free_cb = NULL;
	new->free_cb_arg = NULL;
	new->bhash_data = clone_data;

	return 0;

fail:
	free(clone_data);
	free(new);

	return 1;
}

int
bhash_destroy(
    bhash_t *bhash)
{
	int i;
	bhash_data_t *bhash_data;
	bhash_hash_table_entry_t *hash_table_entry_start, *hash_table_entry;
	bhash_kv_entry_t *kv_entry;
	char *key;
	char *value;

	if (bhash == NULL) {
		errno = EINVAL;
		return 1;
	}
	bhash_data = bhash->bhash_data;
	ASSERT(bhash_data->padding == MAGIC);
	if (bhash->wrap) {
		return 0;
	}
	hash_table_entry_start = HASH_TABLE_START_PTR(bhash_data);
	for (i = 0; i < bhash_data->hash_size; i++) {
		hash_table_entry = hash_table_entry_start + i;
		ASSERT(hash_table_entry->padding == MAGIC);
                if (HASH_KV_ENTRY_START_OFFSET(hash_table_entry) == 0)  {
			continue;
		}
		kv_entry = HASH_KV_ENTRY_START_PTR(hash_table_entry);
		while (1) {
			ASSERT(kv_entry->padding == MAGIC);
			key = KEY_START_PTR(kv_entry);
			value = VALUE_START_PTR(kv_entry);
			if (bhash->free_cb) {
				bhash->free_cb(
				    bhash->free_cb_arg,
				    key,
				    kv_entry->key_actual_size,
				    value,
				    kv_entry->value_actual_size);
			}
			if (NEXT_KV_ENTRY_OFFSET(kv_entry) == 0) {
				break;
			}
			kv_entry = NEXT_KV_ENTRY_PTR(kv_entry);	
		}
	}
	free(bhash_data);
	free(bhash);

	return 0;
}

static int
bhash_get_base(
    bhash_t *bhash,
    char **value,
    size_t *value_size,
    bhash_iterator_t *iterator,
    const char *key,
    size_t key_size,
    bhash_method_flag_t method_flag)
{
	bhash_data_t *bhash_data;
	bhash_hash_table_entry_t *hash_table_entry;
	bhash_kv_entry_t *kv_entry;
	int hash_value;
	char *entry_key;
	char *entry_value;

	ASSERT(bhash != NULL);
	ASSERT(key != NULL);
	ASSERT(key_size > 0);
	ASSERT((method_flag == METHOD_FLAG_GET ||
                method_flag == METHOD_FLAG_GET_ITERATOR));
	IFASSERT(method_flag == METHOD_FLAG_GET_ITERATOR, iterator != NULL);

	bhash_data = bhash->bhash_data;
	ASSERT(bhash_data->padding == MAGIC);
	hash_value = bhash_compute_value(key, key_size, bhash_data->hash_size);
	hash_table_entry = HASH_TABLE_START_PTR(bhash_data)
	hash_table_entry = &hash_table_entry[hash_value];
	ASSERT(hash_table_entry->padding == MAGIC);
	if (HASH_KV_ENTRY_START_OFFSET(hash_table_entry) == 0) {
		switch (method_flag) {
		case METHOD_FLAG_GET:
			*value = NULL;
			if (value_size) {
				*value_size = 0;
			}
			break;
		case METHOD_FLAG_GET_ITERATOR:
			iterator->bhash_data = bhash_data;
			iterator->kv_entry_start = NULL;
			iterator->kv_entry_start_init = NULL;
			break;
		default:
			/* NOTREACHED */
			ABORT("unexpected METHOD_FLAG");
			return 1;
		}
		return 0;
	}
	kv_entry = HASH_KV_ENTRY_START_PTR(hash_table_entry);
	while (1) {
		ASSERT(kv_entry->padding == MAGIC);
		if (kv_entry->key_actual_size != key_size) {
			if (NEXT_KV_ENTRY_OFFSET(kv_entry) == 0) {
				break;
			}
			kv_entry = NEXT_KV_ENTRY_PTR(kv_entry);	
			continue;
		}
		entry_key = KEY_START_PTR(kv_entry);
		if (memcmp(key, entry_key, key_size) == 0) {
			switch (method_flag) {
			case METHOD_FLAG_GET:
				entry_value = VALUE_START_PTR(kv_entry);
				*value = entry_value;
				if (value_size) {
					*value_size = kv_entry->value_actual_size;
				}
				return 0;
			case METHOD_FLAG_GET_ITERATOR:
				iterator->bhash_data = bhash_data;
				iterator->kv_entry_start = kv_entry;
				iterator->kv_entry_start_init = iterator->kv_entry_start;
				return 0;
			default:
				/* NOTREACHED */
				ABORT("unexpected METHOD_FLAG");
				return 1;
			}
			return 0;
		}
                if (NEXT_KV_ENTRY_OFFSET(kv_entry) == 0) {
			break;
		}
		kv_entry = NEXT_KV_ENTRY_PTR(kv_entry);	
	}
	switch (method_flag) {
	case METHOD_FLAG_GET:
		*value = NULL;
		if (value_size) {
			*value_size = 0;
		}
		break;
	case METHOD_FLAG_GET_ITERATOR:
		iterator->bhash_data = bhash_data;
		iterator->kv_entry_start = NULL;
		iterator->kv_entry_start_init = NULL;
		break;
	default:
		/* NOTREACHED */
		ABORT("unexpected METHOD_FLAG");
		return 1;
	}

	return 0;
}

int
bhash_get(
    bhash_t *bhash,
    char **value,
    size_t *value_size,
    const char *key,
    size_t key_size)
{
	if (bhash == NULL ||
	    value == NULL ||
	    key == NULL ||
	    key_size < 1) {
		errno = EINVAL;
		return 1;
	}
	return bhash_get_base(
	    bhash,
	    value,
	    value_size,
	    NULL,
	    key,
	    key_size,
	    METHOD_FLAG_GET);
}

int
bhash_get_iterator(
    bhash_t *bhash,
    bhash_iterator_t *iterator,
    const char *key,
    size_t key_size)
{
	if (bhash == NULL ||
	    iterator == NULL ||
	    key == NULL ||
	    key_size < 1) {
		errno = EINVAL;
		return 1;
	}
	return bhash_get_base(
	    bhash,
	    NULL,
	    NULL,
	    iterator,
	    key,
	    key_size,
	    METHOD_FLAG_GET_ITERATOR);
}

int
bhash_iterator_next(
    bhash_iterator_t *iterator)
{
	bhash_data_t *bhash_data;
	bhash_kv_entry_t *kv_entry_start, *kv_entry;
	char *start_key, *entry_key;
	
	if (iterator == NULL) {
		errno = EINVAL;
		return 1;
	}
	bhash_data = iterator->bhash_data;
	if (iterator->kv_entry_start == NULL) {
		return 1;
	}
	kv_entry_start = iterator->kv_entry_start;
	if (NEXT_KV_ENTRY_OFFSET(kv_entry_start) == 0) {
		iterator->kv_entry_start = NULL;
		return 1;
	}
	kv_entry = NEXT_KV_ENTRY_PTR(kv_entry_start);
	while (1) {
		ASSERT(kv_entry->padding == MAGIC);
		start_key = KEY_START_PTR(kv_entry_start);
		entry_key = KEY_START_PTR(kv_entry);
		if (kv_entry->key_actual_size == kv_entry_start->key_actual_size && 
                    memcmp(start_key, entry_key, kv_entry->key_actual_size) == 0) {
			iterator->kv_entry_start = kv_entry;
			return 0;
		}
                if (NEXT_KV_ENTRY_OFFSET(kv_entry) == 0) {
			break;
		}
		kv_entry = NEXT_KV_ENTRY_PTR(kv_entry);	
	}
	iterator->kv_entry_start = NULL;
	
	return 1;
}

int
bhash_iterator_reset(
    bhash_iterator_t *iterator)
{
	if (iterator == NULL) {
		errno = EINVAL;
		return 1;
	}
	iterator->kv_entry_start = iterator->kv_entry_start_init;

	return 0;
}

int
bhash_iterator_value(
    bhash_iterator_t *iterator,
    char **value,
    size_t *value_size)
{
	bhash_kv_entry_t *kv_entry;
	char *entry_value;
	
	if (iterator == NULL ||
	    value == NULL) {
		errno = EINVAL;
		return 1;
	}
	kv_entry = iterator->kv_entry_start;
	if (kv_entry == NULL) {
		*value = NULL;
		if (value_size) {
			*value_size = 0;
		}
		return 0;
	}
	entry_value = VALUE_START_PTR(kv_entry);
	*value = entry_value;
	if (value_size) {
		*value_size = kv_entry->value_actual_size;
	}

	return 0;
}

static int
bhash_put_base(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size,
    bhash_method_flag_t method_flag,
    void (*replace_cb)(
       void *replace_cb_arg,
       const char *key,
       size_t key_size,
       char *old_value,
       size_t old_value_size,
       char *new_value,
       size_t new_value_size),
    void *replace_cb_arg)
{
	int hash_value;
	bhash_data_t *bhash_data;
	size_t key_align_size, value_align_size, need_size;
	bhash_hash_table_entry_t *hash_table_entry;
	bhash_kv_entry_t *match_kv_entry = NULL;
	bhash_kv_entry_t *new_kv_entry = NULL, *kv_entry;
	bhash_kv_entry_t *search_kv_entry, *prev_search_kv_entry = NULL;
	bhash_kv_entry_t *free_kv_entry, *prev_free_kv_entry = NULL;
	char *match_entry_key, *match_entry_value;
	char *entry_key, *entry_value;

	ASSERT(bhash != NULL);
	ASSERT(key != NULL);
	ASSERT(key_size > 0);
	ASSERT(value != NULL);
	ASSERT(value_size > 0);
	ASSERT((method_flag == METHOD_FLAG_PUT ||
                method_flag == METHOD_FLAG_REPLACE ||
	        method_flag == METHOD_FLAG_APPEND));

	if (bhash->wrap) {
		errno = EINVAL;
		return 1;
	}
	key_align_size = ALIGN_SIZE(key_size);
	value_align_size = ALIGN_SIZE(value_size);
	if (bhash_glow_buffer(bhash, key_align_size, value_align_size)) {
		return 1;
	}
	bhash_data = bhash->bhash_data;
	ASSERT(bhash_data->padding == MAGIC);
	need_size = key_align_size + value_align_size;
	hash_value = bhash_compute_value(key, key_size, bhash_data->hash_size);
	hash_table_entry = HASH_TABLE_START_PTR(bhash_data)
	hash_table_entry = &hash_table_entry[hash_value];
	ASSERT(hash_table_entry->padding == MAGIC);
	if (method_flag != METHOD_FLAG_APPEND) {
		/* search already key */
		if (HASH_KV_ENTRY_START_OFFSET(hash_table_entry) > 0) {
			search_kv_entry = HASH_KV_ENTRY_START_PTR(hash_table_entry);
			while(1) {
				ASSERT(search_kv_entry->padding == MAGIC);
				entry_key = KEY_START_PTR(search_kv_entry);
				if (search_kv_entry->key_actual_size == key_size &&
				    memcmp(key, entry_key, key_size) == 0) {
					match_kv_entry = search_kv_entry;
					break;
				}
				prev_search_kv_entry = search_kv_entry;
                                if (NEXT_KV_ENTRY_OFFSET(search_kv_entry) == 0) {
					break;
				}
				search_kv_entry = NEXT_KV_ENTRY_PTR(search_kv_entry);
			}
		}
	}
	if (match_kv_entry) {
		switch (method_flag) {
		case METHOD_FLAG_PUT:
			errno = EEXIST;
			return 1;
		case METHOD_FLAG_REPLACE:
			/* move to free chain from used chain */
			if (prev_search_kv_entry) {
				prev_search_kv_entry->next_kv_entry = match_kv_entry->next_kv_entry;
			} else {
				hash_table_entry->kv_entry_start = match_kv_entry->next_kv_entry;
			}
			match_kv_entry->next_kv_entry = 0;
			bhash_data->total_kv_entry_count--;
			bhash_data->free_kv_entry_start = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, match_kv_entry);
			if  (FREE_KV_ENTRY_START_OFFSET(bhash_data) == 0) {
				match_kv_entry->next_free_kv_entry = 0;
			} else {
				free_kv_entry = FREE_KV_ENTRY_START_PTR(bhash_data);
				ASSERT(free_kv_entry->padding == MAGIC);
				match_kv_entry->next_free_kv_entry = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, free_kv_entry);
			}
			bhash_data->free_kv_entry_start = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, match_kv_entry);
			bhash_data->free_kv_entry_count++;
			match_entry_key = KEY_START_PTR(match_kv_entry);
			match_entry_value = VALUE_START_PTR(match_kv_entry);
			if (replace_cb) {
				replace_cb(
				    replace_cb_arg,
				    key,
				    key_size,
				    match_entry_value,
				    match_kv_entry->value_actual_size,
				    value,
				    value_size);
			}
			if (bhash->free_cb) {
				bhash->free_cb(
				    bhash->free_cb_arg,
				    match_entry_key,
				    match_kv_entry->key_actual_size,
				    match_entry_value,
				    match_kv_entry->value_actual_size);
			}
			break;
		default:
			break;
		}
	}
	/* find free space */
	if (FREE_KV_ENTRY_START_OFFSET(bhash_data) > 0) {
		free_kv_entry = FREE_KV_ENTRY_START_PTR(bhash_data);
	 	while (1) {
			ASSERT(free_kv_entry->padding == MAGIC);
			if (free_kv_entry->key_align_size + free_kv_entry->value_align_size >= need_size) {
				/* recycle */
				new_kv_entry = free_kv_entry;
				break;
			}
			prev_free_kv_entry = free_kv_entry;
			if (NEXT_FREE_KV_ENTRY_OFFSET(free_kv_entry) == 0) {
				break;
			}
			free_kv_entry = NEXT_FREE_KV_ENTRY_PTR(free_kv_entry);
		}
	}
	/* add new entry */
	if (new_kv_entry) {
		if (prev_free_kv_entry) {
			prev_free_kv_entry->next_free_kv_entry = new_kv_entry->next_free_kv_entry;
		} else {
			bhash_data->free_kv_entry_start = new_kv_entry->next_free_kv_entry;
		}
		bhash_data->free_kv_entry_count--;
	} else { 
		new_kv_entry = LAST_KV_ENTRY_END_PTR(bhash_data);
		new_kv_entry->padding = MAGIC;
		bhash_data->last_kv_entry_end += KV_ENTRY_SIZE(key_align_size, value_align_size);
	}
	new_kv_entry->next_free_kv_entry = 0;
	new_kv_entry->key_actual_size = key_size;
	new_kv_entry->key_align_size = key_align_size;
	new_kv_entry->value_actual_size = value_size;
	new_kv_entry->value_align_size = value_align_size;
	if (HASH_KV_ENTRY_START_OFFSET(hash_table_entry) == 0) {
		new_kv_entry->next_kv_entry = 0;
	} else {
		kv_entry = HASH_KV_ENTRY_START_PTR(hash_table_entry);
		ASSERT(kv_entry->padding == MAGIC);
		new_kv_entry->next_kv_entry = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, kv_entry);
	}
	hash_table_entry->kv_entry_start = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, new_kv_entry);
	bhash_data->total_kv_entry_count++;
	entry_key = KEY_START_PTR(new_kv_entry);
	entry_value = VALUE_START_PTR(new_kv_entry);
	memcpy(entry_key, key, key_size);
	memcpy(entry_value, value, value_size);

	return 0;
}

int
bhash_put(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    const char *value,
    size_t value_size)
{
	if (bhash == NULL ||
	    key == NULL ||
	    key_size < 1 ||
	    value == NULL ||
	    value_size < 1) {
		errno = EINVAL;
		return 1;
	}

	return bhash_put_base(
	    bhash,
	    key,
	    key_size,
	    (char *)value,
	    value_size,
	    METHOD_FLAG_PUT,
	    NULL,
	    NULL);
}

int
bhash_replace(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    char *value,
    size_t value_size,
    void (*replace_cb)(
        void *replace_cb_arg,
        const char *key,
        size_t key_size,
        char *old_value,
        size_t old_value_size,
        char *new_value,
        size_t new_value_size),
    void *replace_cb_arg) 
{
	if (bhash == NULL ||
	    key == NULL ||
	    key_size < 1 ||
	    value == NULL ||
	    value_size < 1) {
		errno = EINVAL;
		return 1;
	}

	return bhash_put_base(
	    bhash,
	    key,
	    key_size,
	    value,
	    value_size,
	    METHOD_FLAG_REPLACE,
	    replace_cb,
	    replace_cb_arg);
}

int
bhash_append(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    const char *value,
    size_t value_size)
{
	if (bhash == NULL ||
	    key == NULL ||
	    key_size < 1 ||
	    value == NULL ||
	    value_size < 1) {
		errno = EINVAL;
		return 1;
	}

	return bhash_put_base(
	    bhash,
	    key,
	    key_size,
	    (char *)value,
	    value_size,
	    METHOD_FLAG_APPEND,
	    NULL,
	    NULL);
}

int
bhash_delete_base(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    int all)
{
	int hash_value;
	bhash_data_t *bhash_data;
	bhash_hash_table_entry_t *hash_table_entry;
	bhash_kv_entry_t *search_kv_entry, *next_search_kv_entry, *prev_search_kv_entry = NULL;
	bhash_kv_entry_t *free_kv_entry;
	char *entry_key, *entry_value;
	int free_count = 0;
	int loop_end = 0;

	ASSERT(bhash != NULL);
	ASSERT(key != NULL);
	ASSERT(key_size > 0);

	if (bhash->wrap) {
		errno = EINVAL;
		return 1;
	}
	bhash_data = bhash->bhash_data;
	ASSERT(bhash_data->padding == MAGIC);
	hash_value = bhash_compute_value(key, key_size, bhash_data->hash_size);
	hash_table_entry = HASH_TABLE_START_PTR(bhash_data)
	hash_table_entry = &hash_table_entry[hash_value];
	ASSERT(hash_table_entry->padding == MAGIC);
	if (HASH_KV_ENTRY_START_OFFSET(hash_table_entry) == 0) {
		errno = ENOENT;
		return 1;
	}
	search_kv_entry = HASH_KV_ENTRY_START_PTR(hash_table_entry);
	while (1) {
		ASSERT(search_kv_entry->padding == MAGIC);
		if (NEXT_KV_ENTRY_OFFSET(search_kv_entry) == 0) {
			loop_end = 1;
		}
		next_search_kv_entry = NEXT_KV_ENTRY_PTR(search_kv_entry);
		entry_key = KEY_START_PTR(search_kv_entry);
		if (search_kv_entry->key_actual_size == key_size &&
		    memcmp(key, entry_key, key_size) == 0) {
			if (prev_search_kv_entry) {
				prev_search_kv_entry->next_kv_entry = search_kv_entry->next_kv_entry;
			} else {
				hash_table_entry->kv_entry_start = search_kv_entry->next_kv_entry;
			}
			search_kv_entry->next_kv_entry = 0;
			bhash_data->total_kv_entry_count--;
			if  (FREE_KV_ENTRY_START_OFFSET(bhash_data) == 0) {
				search_kv_entry->next_free_kv_entry = 0;
			} else {
				free_kv_entry = FREE_KV_ENTRY_START_PTR(bhash_data);
				ASSERT(free_kv_entry->padding == MAGIC);
				search_kv_entry->next_free_kv_entry = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, free_kv_entry);
			} 
			bhash_data->free_kv_entry_start = KV_ENTRY_PTR_TO_KV_ENTRY_OFFSET(bhash_data, search_kv_entry);
			bhash_data->free_kv_entry_count++;
			entry_value = VALUE_START_PTR(search_kv_entry);
			if (bhash->free_cb) {
				bhash->free_cb(
				    bhash->free_cb_arg,
				    entry_key,
				    search_kv_entry->key_actual_size,
				    entry_value,
				    search_kv_entry->value_actual_size);
			}
			free_count++;
			if (!all) {
				break;
			}
		} else {
			prev_search_kv_entry = search_kv_entry;
		}
		if (loop_end) {
			break;
		}
		search_kv_entry = next_search_kv_entry;
	}
	if (free_count == 0) {
		errno = ENOENT;
		return 1;
	}

	return 0;
}

int
bhash_delete(
    bhash_t *bhash,
    const char *key,
    size_t key_size)
{
	if (bhash == NULL ||
	    key == NULL ||
	    key_size < 1) {
		errno = EINVAL;
		return 1;
	}
	return bhash_delete_base(
	    bhash,
	    key,
	    key_size,
	    0);
}


int
bhash_delete_all(
    bhash_t *bhash,
    const char *key,
    size_t key_size)
{
	if (bhash == NULL ||
	    key == NULL ||
	    key_size < 1) {
		errno = EINVAL;
		return 1;
	}
	return bhash_delete_base(
	    bhash,
	    key,
	    key_size,
	    1);
}

int
bhash_foreach(
    bhash_t *bhash,
    void (*foreach_cb)(
        void *foreach_cb_arg,
	int idx,
        const char *key,
        size_t key_size,
        char *value,
        size_t value_size),
    void *foreach_cb_arg)
{
	int i;
	bhash_data_t *bhash_data;
	bhash_hash_table_entry_t *hash_table_entry_start, *hash_table_entry;
	bhash_kv_entry_t *kv_entry;
	char *key;
	char *value;
	int count = 0;

	if (bhash == NULL ||
	    foreach_cb == NULL) {
		errno = EINVAL;
		return 1;
	}
	bhash_data = bhash->bhash_data;
	ASSERT(bhash_data->padding == MAGIC);
	hash_table_entry_start = HASH_TABLE_START_PTR(bhash_data);
	for (i = 0; i < bhash_data->hash_size; i++) {
		hash_table_entry = hash_table_entry_start + i;
		ASSERT(hash_table_entry->padding == MAGIC);
		if (HASH_KV_ENTRY_START_OFFSET(hash_table_entry) == 0) {
			continue;
		}
		kv_entry = HASH_KV_ENTRY_START_PTR(hash_table_entry);
		while (1) {
			ASSERT(kv_entry->padding == MAGIC);
			key = KEY_START_PTR(kv_entry);
			value = VALUE_START_PTR(kv_entry);
			foreach_cb(
			    foreach_cb_arg,
			    count,
			    key,
			    kv_entry->key_actual_size,
			    value,
			    kv_entry->value_actual_size);
			count++;
			if (NEXT_KV_ENTRY_OFFSET(kv_entry) == 0) {
				break;
			}
			kv_entry = NEXT_KV_ENTRY_PTR(kv_entry);	
		}
	}

	return 0;
}

int
bhash_get_entry_count(
    bhash_t *bhash,
    int *entry_count)
{
	bhash_data_t *bhash_data;
 
	if (bhash == NULL) {
		errno = EINVAL;
		return 1;
	}
	bhash_data = bhash->bhash_data;
	*entry_count = bhash_data->total_kv_entry_count;

	return 0;
}

int
bhash_get_bhash_data(
    bhash_t *bhash,
    char **bhash_data,
    size_t *bhash_data_size)
{
	if (bhash == NULL ||
            bhash_data == NULL ||
            bhash_data_size == NULL) {
		errno = EINVAL;
		return 1;
	}
	*bhash_data = (char *)bhash->bhash_data;
	*bhash_data_size = bhash->bhash_data->data_size;

	return 0;
}
