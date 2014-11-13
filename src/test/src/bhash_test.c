#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_macro.h"
#include "bhash.h"

int free_call_count;
int replace_call_count;
int foreach_call_count;

struct free_cb_arg {
	int test;
};
struct replace_cb_arg {
	int test;
};
struct foreach_cb_arg {
	int test;
};

static void
free_cb(void *free_cb_arg, char *key, size_t key_size, char *value, size_t value_size)
{
	struct free_cb_arg *arg = free_cb_arg;
	ASSERT(arg->test == 1);
	free_call_count++;
}

static void
replace_cb(void *replace_cb_arg, const char *key, size_t key_size, char *old_value, size_t old_value_size, char *new_value, size_t new_value_size)
{
	ASSERT(key_size > 3);
	ASSERT(old_value_size > 1);
	ASSERT(new_value_size > 1);
	struct replace_cb_arg *arg = replace_cb_arg;
	ASSERT(arg->test == 2);
	replace_call_count++;
}

static void
foreach_cb(void *foreach_cb_arg, int idx, const char *key, size_t key_size, char *value, size_t value_size)
{
	ASSERT(key_size > 3);
	ASSERT(value_size > 1);
	struct foreach_cb_arg *arg = foreach_cb_arg;
	ASSERT(arg->test == 3);
	foreach_call_count++;
}

int
main(int argc, char*argv[])
{
	int i;
	bhash_t bhash_wrap;
	bhash_t *bhash;
	bhash_iterator_t iterator;
	struct free_cb_arg free_cb_arg = { .test = 1 };
	struct replace_cb_arg replace_cb_arg = { .test = 2 };
	struct foreach_cb_arg foreach_cb_arg = { .test = 3 };
	char *value;
	size_t value_size;
	int entry_count;
	char *bhash_data;
	size_t bhash_data_size;
	char *b;
	char v[32];

        //------
	ASSERT(bhash_create(&bhash, 127, free_cb, &free_cb_arg) == 0);
	ASSERT(bhash_get(bhash, &value, &value_size, "hoge", 5) == 0);
	ASSERT(value == NULL);
	ASSERT(bhash_get_iterator(bhash, &iterator, "fuga", 5) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
	ASSERT(value == NULL);
	ASSERT(bhash_put(bhash, "hoge", 5, "1", 2) == 0);
	ASSERT(bhash_put(bhash, "fuga", 5, "2", 2) == 0);
	ASSERT(bhash_put(bhash, "bar", 4, "3", 2) == 0);
	ASSERT(bhash_replace(bhash, "foo", 4, "4", 2, replace_cb, &replace_cb_arg) == 0);
	ASSERT(bhash_replace(bhash, "hoge", 5, "10", 3, replace_cb, &replace_cb_arg) == 0);
	ASSERT(replace_call_count == 1);
	ASSERT(free_call_count == 1);
	ASSERT(bhash_get_entry_count(bhash, &entry_count) == 0);
	ASSERT(entry_count == 4);
	ASSERT(bhash_get(bhash, &value, &value_size, "hoge", 5) == 0);
        ASSERT(value_size == 3);
        ASSERT(memcmp(value, "10", value_size) == 0);
	ASSERT(bhash_get(bhash, &value, &value_size, "fuga", 5) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "2", value_size) == 0);
	ASSERT(bhash_get(bhash, &value, &value_size, "bar", 4) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "3", value_size) == 0);
	ASSERT(bhash_get(bhash, &value, &value_size, "foo", 4) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "4", value_size) == 0);
	ASSERT(bhash_get_iterator(bhash, &iterator, "foo", 4) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "4", value_size) == 0);
        ASSERT(bhash_iterator_next(&iterator) == 1);
	ASSERT(bhash_delete(bhash, "fuga", 5) == 0);
	ASSERT(free_call_count == 2);
	ASSERT(bhash_delete(bhash, "fuga", 5) == 1);
	ASSERT(free_call_count == 2);
	ASSERT(bhash_put(bhash, "aaaa", 5, "X", 2) == 0);
	ASSERT(bhash_get(bhash, &value, &value_size, "aaaa", 5) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "X", value_size) == 0);
	ASSERT(bhash_delete_all(bhash, "aaaa", 5) == 0);
	ASSERT(free_call_count == 3);
	ASSERT(bhash_delete_all(bhash, "aaaa", 5) == 1);
	ASSERT(free_call_count == 3);
	ASSERT(bhash_get(bhash, &value, &value_size, "aaaa", 5) == 0);
        ASSERT(value == NULL);
	ASSERT(bhash_get(bhash, &value, &value_size, "fuga", 5) == 0);
	ASSERT(value == NULL);
	ASSERT(bhash_get_iterator(bhash, &iterator, "fuga", 5) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
	ASSERT(value == NULL);
	ASSERT(bhash_get_entry_count(bhash, &entry_count) == 0);
	ASSERT(entry_count == 3);
	ASSERT(bhash_foreach(bhash, foreach_cb, &foreach_cb_arg) == 0);
	ASSERT(foreach_call_count == 3);
	ASSERT(bhash_get_bhash_data(bhash, &bhash_data, &bhash_data_size) == 0);
	b = malloc(bhash_data_size);
	ASSERT(b != NULL);
	memcpy(b, bhash_data, bhash_data_size);
	ASSERT(bhash_destroy(bhash) == 0);
	ASSERT(free_call_count == 6);
	ASSERT(bhash_create_wrap_bhash_data(&bhash_wrap, b, bhash_data_size) == 0);
	ASSERT(bhash_get_entry_count(&bhash_wrap, &entry_count) == 0);
	ASSERT(entry_count == 3);
	ASSERT(bhash_get(&bhash_wrap, &value, &value_size, "hoge", 5) == 0);
        ASSERT(value_size == 3);
        ASSERT(memcmp(value, "10", value_size) == 0);
	ASSERT(bhash_get(&bhash_wrap, &value, &value_size, "bar", 4) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "3", value_size) == 0);
	ASSERT(bhash_get(&bhash_wrap, &value, &value_size, "foo", 4) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "4", value_size) == 0);
	ASSERT(bhash_get_iterator(&bhash_wrap, &iterator, "foo", 4) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "4", value_size) == 0);
	ASSERT(bhash_foreach(&bhash_wrap, foreach_cb, &foreach_cb_arg) == 0);
	ASSERT(foreach_call_count == 6);
	ASSERT(bhash_destroy(&bhash_wrap) == 0);
	ASSERT(free_call_count == 6);
	ASSERT(bhash_create(&bhash, 127, free_cb, &free_cb_arg) == 0);
	ASSERT(bhash_append(bhash, "hoge", 5, "1", 2) == 0);
	ASSERT(bhash_append(bhash, "hoge", 5, "2", 2) == 0);
	ASSERT(bhash_append(bhash, "hoge", 5, "3", 2) == 0);
	ASSERT(bhash_append(bhash, "FUGA", 5, "X", 2) == 0);
	ASSERT(bhash_append(bhash, "hoge", 5, "4", 2) == 0);
	ASSERT(bhash_append(bhash, "hoge", 5, "5", 2) == 0);
	ASSERT(bhash_get(bhash, &value, &value_size, "hoge", 5) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "5", value_size) == 0);
	ASSERT(bhash_foreach(bhash, foreach_cb, &foreach_cb_arg) == 0);
	ASSERT(foreach_call_count == 12);
	ASSERT(bhash_get(bhash, &value, &value_size, "FUGA", 5) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "X", value_size) == 0);
	ASSERT(bhash_get_iterator(bhash, &iterator, "hoge", 5) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "5", value_size) == 0);
        ASSERT(bhash_iterator_next(&iterator) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "4", value_size) == 0);
        ASSERT(bhash_iterator_next(&iterator) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "3", value_size) == 0);
        ASSERT(bhash_iterator_next(&iterator) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "2", value_size) == 0);
        ASSERT(bhash_iterator_next(&iterator) == 0);
        ASSERT(bhash_iterator_value(&iterator, &value, &value_size) == 0);
        ASSERT(value_size == 2);
        ASSERT(memcmp(value, "1", value_size) == 0);
        ASSERT(bhash_iterator_next(&iterator) == 1);
	ASSERT(bhash_delete_all(bhash, "hoge", 5) == 0);
	ASSERT(free_call_count == 11);
	ASSERT(bhash_delete_all(bhash, "hoge", 5) == 1);
	ASSERT(free_call_count == 11);
	ASSERT(bhash_get(bhash, &value, &value_size, "hoge", 5) == 0);
        ASSERT(value == NULL);
	ASSERT(bhash_destroy(bhash) == 0);
	ASSERT(free_call_count == 12);
	ASSERT(bhash_create(&bhash, 127, free_cb, &free_cb_arg) == 0);
	for (i = 0; i < 200000; i++) {
		snprintf(v, sizeof(v), "value%06d", i);  
		ASSERT(bhash_put(bhash, v, strlen(v) + 1, "000", 4) == 0);
	}
	ASSERT(bhash_get_entry_count(bhash, &entry_count) == 0);
	ASSERT(entry_count == 200000);
	ASSERT(bhash_destroy(bhash) == 0);
	ASSERT(free_call_count == 200012);

	return 0;
}
