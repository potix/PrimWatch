#ifndef BHASH_H
#define BHASH_H

typedef struct bhash bhash_t;
typedef struct bhash_iterator bhash_iterator_t;
typedef struct bhash_kv_entry bhash_kv_entry_t;
typedef struct bhash_data bhash_data_t;

struct bhash {
	int wrap;
	size_t bhash_data_size;
	bhash_data_t *bhash_data;
	void (*free_cb)(
	    void *free_cb_arg,
	    char *key,
	    size_t key_size,
	    char *value,
	    size_t value_size);
	void *free_cb_arg;
};

struct bhash_iterator{
	bhash_data_t *bhash_data;
	int kv_entry_count_init;
	bhash_kv_entry_t *kv_entry_start_init;
	int kv_entry_count;
	bhash_kv_entry_t *kv_entry_start;
};

int bhash_create(
    bhash_t **bhash,
    int hash_size,
    void (*free_cb)(
        void *free_cb_arg,
        char *key,
        size_t key_size,
        char *value,
        size_t value_size),
    void *free_arg);

int bhash_create_wrap_bhash_data(
    bhash_t *bhash,
    const char *hash_data,
    size_t hash_data_size);

int bhash_destroy(
    bhash_t *bhash);

int bhash_get(
    bhash_t *bhash,
    char **value,
    size_t *value_size,
    const char *key,
    size_t key_size);

int bhash_get_iterator(
    bhash_t *bhash,
    bhash_iterator_t *iterator,
    const char *key,
    size_t key_size);

int bhash_iterator_next(
    bhash_iterator_t *iterator);

int bhash_iterator_reset(
    bhash_iterator_t *iterator);

int bhash_iterator_value(
    bhash_iterator_t *terator,
    char **value,
    size_t *value_size);

int bhash_put(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    const char *value,
    size_t value_size);

int bhash_replace(
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
    void *replace_cb_arg);

int bhash_append(
    bhash_t *bhash,
    const char *key,
    size_t key_size,
    const char *value,
    size_t value_size);

int bhash_delete(
    bhash_t *bhash,
    const char *key,
    size_t key_len);


int bhash_delete_all(
    bhash_t *bhash,
    const char *key,
    size_t key_len);

int bhash_foreach(
    bhash_t *bhash,
    void (*foreach_cb)(
        void *foreach_cb_arg,
	int idx,
        const char *key,
        size_t key_size,
        char *value,
        size_t value_size),
    void *foreach_cb_arg);

int bhash_get_entry_count(
    bhash_t *bhash,
    int *entry_count);

int bhash_get_bhash_data(
    bhash_t *bhash,
    char **bhash_data,
    size_t *bhash_data_size);

#endif
