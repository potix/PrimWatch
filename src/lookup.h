#ifndef LOOKUP_H
#define LOOKUP_H

#include "bson/bson.h"
#include "common_define.h"
#include "accessa.h"
#include "address_util.h"

typedef enum lookup_type lookup_type_t;
typedef struct lookup lookup_t;
typedef struct lookup_params lookup_params_t;
typedef struct lookup_input lookup_input_t;
typedef struct lookup_output_entry lookup_output_entry_t;
typedef struct lookup_output lookup_output_t;

enum lookup_type {
        LOOKUP_TYPE_NATIVE_A = 1,
        LOOKUP_TYPE_NATIVE_AAAA,
        LOOKUP_TYPE_NATIVE_PTR,
};

struct lookup_input {
	const char *name;
	const char *class;
	const char *type;
	const char *id;
	const char *remote_address;
	const char *local_address;
	const char *edns_address;
};

struct lookup_output_entry {
	char name[REVADDRSTRLEN];
	const char *class;
	const char *type;
	unsigned long long ttl;
	const char *id;
	const char *content;
};

struct lookup_output {
	int entry_count;
	lookup_output_entry_t entry[MAX_RECORDS];
};

struct lookup {
	lookup_input_t input;
	lookup_output_t output;
	accessa_t *accessa;
	shared_buffer_t *accessa_buffer;
	lookup_params_t *params;
};

int lookup_initialize(
    lookup_t *lookup,
    accessa_t *accessa);

int lookup_setup_input(
    lookup_t *lookup,
    const char *name,
    const char *class,
    const char *type,
    const char *id,
    const char *remote_address,
    const char *local_address,
    const char *edns_address);
    
int lookup_native(
    lookup_t *lookup);

int lookup_output_foreach(
    lookup_t *lookup,
    void (*output_foreach_cb)(
        void *output_foreach_cb_arg,
        const char *name,
        const char *class,
        const char *type,
        unsigned long long ttl,
        const char *id,
        const char *content),
    void *output_foreach_cb_arg);

int lookup_get_output_len(
    lookup_t *lookup,
    int *output_len);

int lookup_finalize(
    lookup_t *lookup);

#endif
