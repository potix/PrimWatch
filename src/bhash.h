#ifndef BHASH_H
#define BHASH_H

typedef struct bhash bhash_t;
typedef struct bhash_iterator bhash_iterator_t;
typedef struct bhash_kv_entry bhash_kv_entry_t;
typedef struct bhash_data bhash_data_t;

struct bhash {
	int wrap;
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
	bhash_kv_entry_t *kv_entry_start_init;
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
    const char *bhash_data,
    size_t hash_data_size);

int bhash_clone(
    bhash_t **bhash,
    const char *bhash_data);

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

/*
 * blist is alias of bhash which size of hash is 1 
 */
typedef bhash_t blist_t;
typedef bhash_iterator_t blist_iterator_t;
typedef bhash_kv_entry_t blist_kv_entry_t;
typedef bhash_data_t blist_data_t;
#define blist_create(blist, free_cb, free_arg) \
	bhash_create((blist), 1, (free_cb), (free_arg))
#define blist_create_wrap_bhash_data bhash_create_wrap_bhash_data
#define blist_clone bhash_clone
#define blist_destroy bhash_destroy
#define blist_get bhash_get
#define blist_get bhash_get
#define blist_get_iterator bhash_get_iterator
#define blist_iterator_next bhash_iterator_next
#define blist_iterator_reset bhash_iterator_reset
#define blist_iterator_value bhash_iterator_value
#define blist_put bhash_put
#define blist_replace bhash_replace
#define blist_append bhash_append
#define blist_delete bhash_delete
#define blist_delete_all bhash_delete_all
#define blist_foreach_all bhash_foreach_all
#define blist_get_entry_count bhash_get_entry_count
#define blist_get_blist_data bhash_get_bhash_data

#endif
