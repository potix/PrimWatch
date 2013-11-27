#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>

#include "common_macro.h"
#include "json_parser.h"
#include "logger.h"

typedef enum json_parser_validation_rule_type json_parser_validation_rule_type_t;
typedef enum json_parser_type json_parser_type_t;
typedef struct json_parser_state json_parser_state_t;
typedef struct json_parser_validation_rule json_parser_validation_rule_t;
typedef struct json_parser_validation_rule_boolean json_parser_validation_rule_boolean_t;
typedef struct json_parser_validation_rule_integer json_parser_validation_rule_integer_t;
typedef struct json_parser_validation_rule_double json_parser_validation_rule_double_t;
typedef struct json_parser_validation_rule_string json_parser_validation_rule_string_t;

enum json_parser_validation_rule_type {
	VALIDATION_RULE_TYPE_BOOLEAN = 1,
	VALIDATION_RULE_TYPE_INTEGER,
	VALIDATION_RULE_TYPE_DOUBLE,
	VALIDATION_RULE_TYPE_STRING
};

enum json_parser_type {
        PARSE_TYPE_NULL       = 0x001,
        PARSE_TYPE_BOOLEAN    = 0x002,
        PARSE_TYPE_INTEGER    = 0x004,
        PARSE_TYPE_DOUBLE     = 0x008,
        PARSE_TYPE_NUMBER     = 0x010,
        PARSE_TYPE_STRING     = 0x020,
        PARSE_TYPE_MAP_START  = 0x040,
        PARSE_TYPE_MAP_END    = 0x080,
        PARSE_TYPE_MAP_KEY    = 0x100,
        PARSE_TYPE_LIST_START = 0x200,
        PARSE_TYPE_LIST_END   = 0x300
};

struct json_parser_state {
	json_parser_type_t parse_type;
	char *map_key;
        long long array_index;
	TAILQ_ENTRY(json_parser_state) next;
};
struct json_parser_validation_rule {
	json_parser_validation_rule_type_t rule_type;
	LIST_ENTRY(json_parser_validation_rule) next;
	regex_t preg;
};

struct json_parser_validation_rule_boolean {
	json_parser_validation_rule_type_t rule_type;
	LIST_ENTRY(json_parser_validation_rule) next;
	regex_t preg;
	int (*validate_callback)(
            void *validate_callback_arg,
            const char *path,
	    const char *key,
            int b, bson *bson);
	void *validate_callback_arg;
};

struct json_parser_validation_rule_integer {
	json_parser_validation_rule_type_t rule_type;
	LIST_ENTRY(json_parser_validation_rule) next;
	regex_t preg;
	long long min;
	long long max;
	int (*validate_callback)(
            void *validate_callback_arg,
            const char *path,
	    const char *key,
            long long l,
            bson *bson);
	void *validate_callback_arg;
};

struct json_parser_validation_rule_double {
	json_parser_validation_rule_type_t rule_type;
	LIST_ENTRY(json_parser_validation_rule) next;
	regex_t preg;
	double min;
	double max;
	int (*validate_callback)(
            void *validate_callback_arg,
            const char *path,
	    const char *key,
            double d,
            bson *bson);
	void *validate_callback_arg;
};

struct json_parser_validation_rule_string {
	json_parser_validation_rule_type_t rule_type;
	LIST_ENTRY(json_parser_validation_rule) next;
	regex_t preg;
	size_t minlen;
	size_t maxlen;
	const char **candidate;
	int ncandidate;
	int (*validate_callback)(
            void *validate_callback_arg,
            const char *path,
	    const char *key,
            const char *s,
	    size_t len,
            bson *bson);
	void *validate_callback_arg;
};

struct json_parser {
	TAILQ_HEAD(json_parser_state_stack_head, json_parser_state) state_stack_head;
	LIST_HEAD(json_parser_validation_rule_head, json_parser_validation_rule) validation_rule_head;
	bson *bson;
};

static json_parser_validation_rule_t *json_parser_get_validate_rule(
    json_parser_t *json_parser,
    const char *path);
static int json_parser_validate_boolean(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    int b);
static int json_parser_validate_integer(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    long long l);
static int json_parser_validate_double(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    double d);
static int json_parser_validate_string(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    const char *s,
    size_t len);
static int json_parser_state_create(
    json_parser_state_t **state,
    json_parser_type_t parse_type,
    const unsigned char *map_key,
    size_t map_key_len);
static void json_parser_state_destroy(json_parser_state_t *state);
static void json_parser_push_state(json_parser_t *json_parser, json_parser_state_t *state);
static json_parser_state_t *json_parser_pop_state(json_parser_t *json_parser);
static json_parser_state_t *json_parser_get_state(json_parser_t *json_parser, int i);
static void json_parser_clean_state_stack(json_parser_t *json_parser);
static void json_parser_get_path( json_parser_t *json_parser, char *path, size_t path_size);
static int json_parser_null(void *ctx); 
static int json_parser_boolean(void *ctx, int boolean);
#if YAJL_MAJOR <= 1
static int json_parser_integer(void *ctx, long l);
#else
static int json_parser_integer(void *ctx, long long ll);
#endif
static int json_parser_double(void *ctx, double d);
#if YAJL_MAJOR <= 1
static int json_parser_string( void *ctx, const unsigned char *val, unsigned int len);
static int json_parser_map_key( void *ctx, const unsigned char *val, unsigned int len);
#else
static int json_parser_string(void *ctx, const unsigned char *val, size_t len);
static int json_parser_map_key(void *ctx, const unsigned char *val, size_t len);
#endif
static int json_parser_start_map(void *ctx);
static int json_parser_end_map(void *ctx);
static int json_parser_start_array(void *ctx);
static int json_parser_end_array(void *ctx);

static yajl_callbacks parse_callbacks = {
	json_parser_null,
	json_parser_boolean,
	json_parser_integer,
	json_parser_double,
	NULL,
	json_parser_string,
	json_parser_start_map,
	json_parser_map_key,
	json_parser_end_map,
	json_parser_start_array,
	json_parser_end_array
};


static json_parser_validation_rule_t *
json_parser_get_validate_rule(
    json_parser_t *json_parser,
    const char *path)
{
	json_parser_validation_rule_t *validation_rule;
	regmatch_t match[1];

	ASSERT(json_parser != NULL);
	ASSERT(path != NULL);
	LIST_FOREACH(validation_rule, &json_parser->validation_rule_head, next) {
		if (regexec(&validation_rule->preg, path, sizeof(match)/sizeof(match[0]) , match, 0) != 0) {
			continue;
		}
		return validation_rule;
	}

	return NULL;
}


static int 
json_parser_validate_boolean(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    int b)
{
	json_parser_validation_rule_t *validation_rule;
	json_parser_validation_rule_boolean_t *validation_rule_boolean;

	ASSERT(json_parser != NULL);
	ASSERT(path != NULL);
	validation_rule = json_parser_get_validate_rule(json_parser, path);
	if (validation_rule == NULL) {
		return 0;
	}
	if (validation_rule->rule_type != VALIDATION_RULE_TYPE_BOOLEAN) {
		LOG(LOG_LV_ERR, "%s, rule type of validation is mismatch (%d, %d)", key, validation_rule->rule_type, VALIDATION_RULE_TYPE_BOOLEAN);
		return 1;
	}
	validation_rule_boolean = (json_parser_validation_rule_boolean_t *)validation_rule;
	if (validation_rule_boolean->validate_callback) {
		if (validation_rule_boolean->validate_callback(
		    validation_rule_boolean->validate_callback_arg,
		    path,
                    key,
		    b,
		    json_parser->bson) != JSON_PARSER_VALIDATION_SUCCESS) {
			return 1;
		}
	}
	
	return 0;
}

static int 
json_parser_validate_integer(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    long long l)
{
	json_parser_validation_rule_t *validation_rule;
	json_parser_validation_rule_integer_t *validation_rule_integer;

	ASSERT(json_parser != NULL);
	ASSERT(path != NULL);
	validation_rule = json_parser_get_validate_rule(json_parser, path);
	if (validation_rule == NULL) {
		return 0;
	}
	if (validation_rule->rule_type != VALIDATION_RULE_TYPE_INTEGER) {
		LOG(LOG_LV_ERR, "%s: rule type of validation is mismatch (%d, %d)", key, validation_rule->rule_type, VALIDATION_RULE_TYPE_INTEGER);
		return 1;
	}
	validation_rule_integer = (json_parser_validation_rule_integer_t *)validation_rule;
	if (l < validation_rule_integer->min) {
		LOG(LOG_LV_ERR, "%s: value is too small (%lld < %lld)", key, l, validation_rule_integer->min);
		return 1;
	}
	if (l > validation_rule_integer->max) {
		LOG(LOG_LV_ERR, "%s: value is too small (%lld > %lld)", key, l, validation_rule_integer->max);
		return 1;
	}
	if (validation_rule_integer->validate_callback) {
		if (validation_rule_integer->validate_callback(
		    validation_rule_integer->validate_callback_arg,
		    path,
                    key,
		    l,
		    json_parser->bson) != JSON_PARSER_VALIDATION_SUCCESS) {
			return 1;
		}
	}
	
	return 0;
}

static int 
json_parser_validate_double(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    double d)
{
	json_parser_validation_rule_t *validation_rule;
	json_parser_validation_rule_double_t *validation_rule_double;

	ASSERT(json_parser != NULL);
	ASSERT(path != NULL);
	validation_rule = json_parser_get_validate_rule(json_parser, path);
	if (validation_rule == NULL) {
		return 0;
	}
	if (validation_rule->rule_type != VALIDATION_RULE_TYPE_DOUBLE) {
		LOG(LOG_LV_ERR, "%s: rule type of validation is mismatch (%d, %d)", key, validation_rule->rule_type, VALIDATION_RULE_TYPE_DOUBLE);
		return 1;
	}
	validation_rule_double = (json_parser_validation_rule_double_t *)validation_rule;
	if (d < validation_rule_double->min) {
		LOG(LOG_LV_ERR, "%s: value is too small (%lf < %lf)", key, d, validation_rule_double->min);
		return 1;
	}
	if (d > validation_rule_double->max) {
		LOG(LOG_LV_ERR, "%s: value is too big (%lf > %lf)", key, d , validation_rule_double->max);
		return 1;
	}
	if (validation_rule_double->validate_callback) {
		if (validation_rule_double->validate_callback(
		    validation_rule_double->validate_callback_arg,
		    path,
                    key,
		    d,
		    json_parser->bson) != JSON_PARSER_VALIDATION_SUCCESS) {
			return 1;
		}
	}
	
	return 0;
}

static int 
json_parser_validate_string(
    json_parser_t *json_parser,
    const char *path,
    const char *key,
    const char *s,
    size_t len)
{
	json_parser_validation_rule_t *validation_rule;
	json_parser_validation_rule_string_t *validation_rule_string;
	int i;

	ASSERT(json_parser != NULL);
	ASSERT(path != NULL);
	validation_rule = json_parser_get_validate_rule(json_parser, path);
	if (validation_rule == NULL) {
		return 0;
	}
	if (validation_rule->rule_type != VALIDATION_RULE_TYPE_STRING) {
		LOG(LOG_LV_ERR, "%s: rule type of validation is mismatch (%d, %d)", key, validation_rule->rule_type, VALIDATION_RULE_TYPE_STRING);
		return 1;
	}
	validation_rule_string = (json_parser_validation_rule_string_t *)validation_rule;
	if (validation_rule_string->candidate) {
		for (i = 0; i < validation_rule_string->ncandidate; i++) {
			if (strcmp(s, validation_rule_string->candidate[i]) == 0) {
				break;
			}
		}
		if (i == validation_rule_string->ncandidate) {
			LOG(LOG_LV_ERR, "%s: not found match candidate (%s)", key, s);
			return 1;
		}
	}
	if (len < validation_rule_string->minlen) {
		LOG(LOG_LV_ERR, "%s: length is too short (%zd < %zd)", key, len, validation_rule_string->minlen);
		return 1;
	}
	if (len > validation_rule_string->maxlen) {
		LOG(LOG_LV_ERR, "%s: length is too long (%zd > %zd)", key, len, validation_rule_string->maxlen);
		return 1;
	}
	if (validation_rule_string->validate_callback) {
		if (validation_rule_string->validate_callback(
		    validation_rule_string->validate_callback_arg,
		    path,
		    key,
		    s,
		    len,
		    json_parser->bson) != JSON_PARSER_VALIDATION_SUCCESS) {
			return 1;
		}
	}

	return 0;
}

static void
json_parser_get_path(
    json_parser_t *json_parser,
    char *path,
    size_t path_size)
{
	json_parser_state_t *state;
	int len = 0;
	int tmplen;

	ASSERT(json_parser != NULL);
	ASSERT(path != NULL);
	ASSERT(path_size > 0);
	
	path[0] = '\0';
        TAILQ_FOREACH_REVERSE(state, &json_parser->state_stack_head, json_parser_state_stack_head, next) {
		if (state->parse_type == PARSE_TYPE_MAP_KEY) {
			tmplen = snprintf(&path[len], path_size - len, "%s.", state->map_key);
			len += tmplen;
		} else if (state->parse_type == PARSE_TYPE_LIST_START) {
			tmplen = snprintf(&path[len], path_size - len, "%lld.", state->array_index);
			len += tmplen;
		}
        }
	if (len > 0) {
		path[len - 1] = '\0';
	}
} 

static void
json_parser_push_state(
    json_parser_t *json_parser,
    json_parser_state_t *state)
{
	ASSERT(json_parser != NULL);
	ASSERT(state != NULL);

	TAILQ_INSERT_HEAD(&json_parser->state_stack_head, state, next);
}

static json_parser_state_t *
json_parser_pop_state(
    json_parser_t *json_parser)
{
	json_parser_state_t *state;

	ASSERT(json_parser != NULL);

	state = TAILQ_FIRST(&json_parser->state_stack_head);
	if (state != NULL) {
		TAILQ_REMOVE(&json_parser->state_stack_head, state, next);
	}

	return state;
}

static json_parser_state_t *
json_parser_get_state(
    json_parser_t *json_parser,
    int i)
{
	json_parser_state_t *state;

	ASSERT(json_parser != NULL);
	ASSERT(i >= 0);

        TAILQ_FOREACH(state, &json_parser->state_stack_head, next) {
		if (i == 0) {
			return state;
		}
		i -= 1;
        }

	return NULL;
}

void
json_parser_clean_state_stack(
    json_parser_t *json_parser)
{
	json_parser_state_t *state, *state_next;

	state = TAILQ_FIRST(&json_parser->state_stack_head);
	while(state) {
		state_next = TAILQ_NEXT(state, next);
		TAILQ_REMOVE(&json_parser->state_stack_head, state, next);
		json_parser_state_destroy(state);
		state = state_next;
	}
}
 
static int
json_parser_state_create(
    json_parser_state_t **state,
    json_parser_type_t parse_type,
    const unsigned char *map_key,
    size_t map_key_len)
{
	json_parser_state_t *new_state;
	char *s = NULL;

	ASSERT(state != NULL);

	new_state = malloc(sizeof(json_parser_state_t));
	if (new_state == NULL) {
		goto fail;
	}
	memset(new_state, 0, sizeof(json_parser_state_t));
	if (map_key != NULL) {
		s = malloc(map_key_len + 1);
		if (s == NULL) {
			goto fail;
		}
		memcpy(s, map_key, map_key_len);
		s[map_key_len] = '\0';
		new_state->map_key = s;
	}
	new_state->parse_type = parse_type;
	new_state->array_index = 0;
	*state = new_state;
	
	return 0;

fail:
	free(s);
	free(new_state);

	return 1;
}

static void
json_parser_state_destroy(
    json_parser_state_t *state)
{
	ASSERT(state != NULL);

	if (state->map_key) {
		free(state->map_key);
	}	
	free(state);
}

static int
json_parser_null(
    void *ctx)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state;
	char idx_str[32];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		return 0;
	}
	switch (latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (bson_append_null(json_parser->bson, latest_state->map_key) != BSON_OK) {
			return 0;
		} 
		latest_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(latest_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (bson_append_null(json_parser->bson, idx_str) != BSON_OK) {
			return 0;
		}
		latest_state->array_index += 1;	
		return 1;
	default:
		ABORT("unexpected parse type");
		return 0;
	}
}

static int
json_parser_boolean(
    void *ctx,
    int b)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state;
	char idx_str[32];
	char path[MAX_JSON_PATH_LEN];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	json_parser_get_path(json_parser, path, sizeof(path));
	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		return 0;
	}
	switch (latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (json_parser_validate_boolean(json_parser, path, latest_state->map_key, b)) {
			return 0;
		}
		if (bson_append_bool(json_parser->bson, latest_state->map_key, b) != BSON_OK) {
			return 0;
		} 
		latest_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(latest_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (json_parser_validate_boolean(json_parser, path, idx_str, b)) {
			return 0;
		}
		if (bson_append_bool(json_parser->bson, idx_str, b) != BSON_OK) {
			return 0;
		}
		latest_state->array_index += 1;	
		return 1;
	default:
		ABORT("unexpected parse type");
		return 0;
	}
}

static int
json_parser_integer(
    void *ctx,
#if YAJL_MAJOR <= 1
    long l)
#else
    long long l)
#endif
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state;
	char idx_str[32];
	char path[MAX_JSON_PATH_LEN];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	json_parser_get_path(json_parser, path, sizeof(path));
	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		return 0;
	}
	switch (latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (json_parser_validate_integer(json_parser, path, latest_state->map_key, (long long)l)) {
			return 0;
		}
		if (bson_append_long(json_parser->bson, latest_state->map_key, l) != BSON_OK) {
			return 0;
		} 
		latest_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(latest_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (json_parser_validate_integer(json_parser, path, idx_str, (long long)l)) {
			return 0;
		}
		if (bson_append_long(json_parser->bson, idx_str, l) != BSON_OK) {
			return 0;
		}
		latest_state->array_index += 1;	
		return 1;
	default:
		ABORT("unexpected parse type");
		return 0;
	}
}

static int
json_parser_double(
    void *ctx,
    double d)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state;
	char idx_str[32];
	char path[MAX_JSON_PATH_LEN];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	json_parser_get_path(json_parser, path, sizeof(path));
	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		return 0;
	}
	switch (latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (json_parser_validate_double(json_parser, path, latest_state->map_key, d)) {
			return 0;
		}
		if (bson_append_double(json_parser->bson, latest_state->map_key, d) != BSON_OK) {
			return 0;
		} 
		latest_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(latest_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (json_parser_validate_double(json_parser, path, idx_str, d)) {
			return 0;
		}
		if (bson_append_double(json_parser->bson, idx_str, d) != BSON_OK) {
			return 0;
		}
		latest_state->array_index += 1;	
		return 1;
	default:
		ABORT("unexpected parse type");
		return 0;
	}
}

static int
json_parser_string(
    void *ctx,
    const unsigned char *val,
#if YAJL_MAJOR <= 1
    unsigned int len)
#else
    size_t len)
#endif
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state;
	char *s = NULL;
	char idx_str[32];
	char path[MAX_JSON_PATH_LEN];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	json_parser_get_path(json_parser, path, sizeof(path));
	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		return 0;
	}
	if ((s = malloc(len + 1)) == NULL) {
		return 0;
	}
	memcpy(s, val, len);
	s[len] = '\0';
	switch (latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (json_parser_validate_string(json_parser, path, latest_state->map_key, (const char *)s, len)) {
			goto fail;
		}
		if (bson_append_string(json_parser->bson, latest_state->map_key, s) != BSON_OK) {
			goto fail;
		} 
		latest_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(latest_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (json_parser_validate_string(json_parser, path, idx_str, (const char *)val, len)) {
			goto fail;
		}
		if (bson_append_string(json_parser->bson, idx_str, s) != BSON_OK) {
			goto fail;
		}
		latest_state->array_index += 1;	
		return 1;
	default:
		ABORT("unexpected parse type");
		goto fail;
	}

fail:

	free(s);

	return 0;

}

static int
json_parser_map_key(
    void *ctx,
    const unsigned char *val,
#if YAJL_MAJOR <= 1
    unsigned int len)
#else
    size_t len)
#endif
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state, *state;

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL || latest_state->parse_type != PARSE_TYPE_MAP_START) {
		return 0;
	}
	if (json_parser_state_create(&state, PARSE_TYPE_MAP_KEY, val, (size_t)len)) {
		return 0;
	}
	json_parser_push_state(json_parser, state);
	
	return 1;
}

static int
json_parser_start_map(void *ctx)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state, *state;
	char idx_str[32];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	if (json_parser_state_create(&state, PARSE_TYPE_MAP_START, NULL, 0)) {
		return 0;
	}
	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		// start 
		json_parser_push_state(json_parser, state);
		return 1;
	}
	switch(latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (bson_append_start_object(json_parser->bson, latest_state->map_key) != BSON_OK) {
			goto fail;
		}
		break; 
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (bson_append_start_object(json_parser->bson, idx_str) != BSON_OK) {
			goto fail;
		}	
		break;
	default:
		ABORT("unexpected parse type");
		goto fail;
	}
	json_parser_push_state(json_parser, state);

	return 1;

fail:

	json_parser_state_destroy(state);

	return 0;
}

static int
json_parser_end_map(void *ctx)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *prev_state, *state;

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	state = json_parser_pop_state(json_parser);
	ASSERT(state->parse_type == PARSE_TYPE_MAP_START);
	bson_append_finish_object(json_parser->bson);
	prev_state = json_parser_get_state(json_parser, 0);
	if (prev_state == NULL) {
		// end
		return 1;
	}
	switch(prev_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		prev_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(prev_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		prev_state->array_index += 1;
		return 1;
	default:
		ABORT("unexpected parse type");
		return 0;
	}
	json_parser_state_destroy(state);
}

static int
json_parser_start_array(void *ctx)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *latest_state, *state;
	char idx_str[32];

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	if (json_parser_state_create(&state, PARSE_TYPE_LIST_START, NULL, 0)) {
		return 0;
	}
	latest_state = json_parser_get_state(json_parser, 0);
	if (latest_state == NULL) {
		return 0;
	}
	switch(latest_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		if (bson_append_start_array(json_parser->bson, latest_state->map_key) != BSON_OK) {
			goto fail;
		}
		break;
	case PARSE_TYPE_LIST_START:
		snprintf(idx_str, sizeof(idx_str), "%lld", latest_state->array_index);
		if (bson_append_start_array(json_parser->bson, idx_str) != BSON_OK) {
			goto fail;
		}
		break;
	default:
		ABORT("unexpected parse type");
		goto fail;
	}
	json_parser_push_state(json_parser, state);

	return 1;
	
fail:

	json_parser_state_destroy(state);

	return 0;
	
}

static int
json_parser_end_array(void *ctx)
{
	json_parser_t *json_parser = ctx;
	json_parser_state_t *prev_state, *state;

	ASSERT(json_parser != NULL);
	ASSERT(json_parser->bson != NULL);

	state = json_parser_pop_state(json_parser);
	ASSERT(state->parse_type == PARSE_TYPE_LIST_START);
	bson_append_finish_array(json_parser->bson);
	prev_state = json_parser_get_state(json_parser, 0);
	if (prev_state == NULL) {
		return 0;
	}
	switch(prev_state->parse_type) {
	case PARSE_TYPE_MAP_KEY:
		prev_state = json_parser_pop_state(json_parser);
		json_parser_state_destroy(prev_state);
		return 1;
	case PARSE_TYPE_LIST_START:
		prev_state->array_index += 1;
		return 1;
	default:
		ABORT("unexpected parse type");
		return 0;
	}
	json_parser_state_destroy(state);
}

int
json_parser_create(
    json_parser_t **json_parser)
{
	json_parser_t *new;

	if (json_parser == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(json_parser_t));
	if (new == NULL) {
		return 1;
	}
	memset(new, 0, sizeof(json_parser_t));
	LIST_INIT(&new->validation_rule_head);
	*json_parser = new;
		
	return 0;
}

int
json_parser_destroy(
    json_parser_t *json_parser)
{
	json_parser_validation_rule_t *validation_rule, *validation_rule_next;

	if (json_parser == NULL) {
		errno = EINVAL;
		return 1;
	}
	validation_rule = LIST_FIRST(&json_parser->validation_rule_head);
	while (validation_rule) {
		validation_rule_next = LIST_NEXT(validation_rule, next);
		LIST_REMOVE(validation_rule, next);
		regfree(&validation_rule->preg);
		free(validation_rule);
		validation_rule = validation_rule_next;
	}
	free(json_parser);

	return 0;
}

int
json_parser_add_validation_boolean(
    json_parser_t *json_parser,
    const char *regex_path,
    int (*validate_callback)(
        void *validate_callback_arg,
        const char *path,
        const char *key,
        int b,
        bson *bson),
    void *validate_callback_arg)
{
	json_parser_validation_rule_boolean_t *validation_rule_boolean = NULL;
	json_parser_validation_rule_t *validation_rule;

	if (json_parser == NULL ||
	    regex_path == NULL) {
		errno = EINVAL;
		return 1;
	}
	validation_rule_boolean = malloc(sizeof(json_parser_validation_rule_boolean_t));
	if (validation_rule_boolean == NULL) {
		goto fail;
	}
	memset(validation_rule_boolean, 0, sizeof(json_parser_validation_rule_boolean_t));
	if (regcomp(&validation_rule_boolean->preg, regex_path, REG_EXTENDED|REG_NEWLINE)  != 0) {
		goto fail;
	}
	validation_rule_boolean->rule_type = VALIDATION_RULE_TYPE_BOOLEAN;
	validation_rule_boolean->validate_callback = validate_callback;
	validation_rule_boolean->validate_callback_arg = validate_callback_arg;
	validation_rule = (json_parser_validation_rule_t *)validation_rule_boolean;
	LIST_INSERT_HEAD(&json_parser->validation_rule_head, validation_rule, next);

	return 0;

fail:
	free(validation_rule_boolean);

	return 1;
}

int
json_parser_add_validation_integer(
    json_parser_t *json_parser,
    const char *regex_path,
    long long min,
    long long max,
    int (*validate_callback)(
        void *validate_callback_arg,
        const char *path,
        const char *key,
        long long l,
        bson *bson),
    void *validate_callback_arg)
{
	json_parser_validation_rule_integer_t *validation_rule_integer = NULL;
	json_parser_validation_rule_t *validation_rule;

	if (json_parser == NULL ||
	    regex_path == NULL) {
		errno = EINVAL;
		return 1;
	}
	validation_rule_integer = malloc(sizeof(json_parser_validation_rule_integer_t));
	if (validation_rule_integer == NULL) {
		goto fail;	
	}
	memset(validation_rule_integer, 0, sizeof(json_parser_validation_rule_integer_t));
	if (regcomp(&validation_rule_integer->preg, regex_path, REG_EXTENDED|REG_NEWLINE)  != 0) {
		goto fail;
	}
	validation_rule_integer->rule_type = VALIDATION_RULE_TYPE_INTEGER;
	validation_rule_integer->min = min;
	validation_rule_integer->max = max;
	validation_rule_integer->validate_callback = validate_callback;
	validation_rule_integer->validate_callback_arg = validate_callback_arg;
	validation_rule = (json_parser_validation_rule_t *)validation_rule_integer;
	LIST_INSERT_HEAD(&json_parser->validation_rule_head, validation_rule, next);

	return 0;

fail:
	free(validation_rule_integer);

	return 1;
}

int
json_parser_add_validation_double(
    json_parser_t *json_parser,
    const char *regex_path,
    double min,
    double max,
    int (*validate_callback)(
        void *validate_callback_arg,
        const char *path,
        const char *key,
        double d,
        bson *bson),
    void *validate_callback_arg)
{
	json_parser_validation_rule_double_t *validation_rule_double = NULL;
	json_parser_validation_rule_t *validation_rule;
	if (json_parser == NULL ||
	    regex_path == NULL) {
		errno = EINVAL;
		return 1;
	}

	validation_rule_double = malloc(sizeof(json_parser_validation_rule_double_t));
	if (validation_rule_double == NULL) {
		goto fail;
	}
	memset(validation_rule_double, 0, sizeof(json_parser_validation_rule_double_t));
	if (regcomp(&validation_rule_double->preg, regex_path, REG_EXTENDED|REG_NEWLINE)  != 0) {
		goto fail;
	}
	validation_rule_double->rule_type = VALIDATION_RULE_TYPE_DOUBLE;
	validation_rule_double->min = min;
	validation_rule_double->max = max;
	validation_rule_double->validate_callback = validate_callback;
	validation_rule_double->validate_callback_arg = validate_callback_arg;
	validation_rule = (json_parser_validation_rule_t *)validation_rule_double;
	LIST_INSERT_HEAD(&json_parser->validation_rule_head, validation_rule, next);

	return 0;
fail:
	free(validation_rule_double);

	return 1;
}

int
json_parser_add_validation_string(
    json_parser_t *json_parser,
    const char *regex_path,
    size_t minlen,
    size_t maxlen,
    const char *candidate[],
    int ncandidate,
    int (*validate_callback)(void *validate_callback_arg, const char *path, const char *key, const char *s, size_t len, bson *bson),
    void *validate_callback_arg)
{
	json_parser_validation_rule_string_t *validation_rule_string = NULL;
	json_parser_validation_rule_t *validation_rule;
	if (json_parser == NULL ||
	    regex_path == NULL ||
	    minlen < 0 ||
	    maxlen < 0 ||
	    ncandidate < 0) {
		errno = EINVAL;
		return 1;
	}

	validation_rule_string = malloc(sizeof(json_parser_validation_rule_string_t));
	if (validation_rule_string == NULL) {
		goto fail;
	}
	memset(validation_rule_string, 0, sizeof(json_parser_validation_rule_string_t));
	if (regcomp(&validation_rule_string->preg, regex_path, REG_EXTENDED|REG_NEWLINE)  != 0) {
		goto fail;
	}
	validation_rule_string->rule_type = VALIDATION_RULE_TYPE_STRING;
	validation_rule_string->minlen = minlen;
	validation_rule_string->maxlen = maxlen;
	validation_rule_string->candidate = candidate;
	validation_rule_string->ncandidate = ncandidate;
	validation_rule_string->validate_callback = validate_callback;
	validation_rule_string->validate_callback_arg = validate_callback_arg;
	validation_rule = (json_parser_validation_rule_t *)validation_rule_string;
	LIST_INSERT_HEAD(&json_parser->validation_rule_head, validation_rule, next);

	return 0;
fail:
	free(validation_rule_string);

	return 1;
}

int
json_parser_parse(
    json_parser_t *json_parser,
    const char *file_path,
    bson *bson)
{
	yajl_handle handle = NULL;
	yajl_status status;
	struct stat file_stat;
	int fd = -1;
	unsigned char *fdata = NULL;
	size_t max_read_len, read_len;
	unsigned char *err;
	int finish = 0;

	if (json_parser == NULL ||
	    file_path == NULL ||
	    bson == NULL) {
		errno = EINVAL;
		return 1;
	}
	json_parser->bson = bson;
	TAILQ_INIT(&json_parser->state_stack_head);
	if (stat(file_path, &file_stat)) {
		goto fail;	
	}
#if YAJL_MAJOR <= 1
	yajl_parser_config cfg = { 1, 1 };
	handle = yajl_alloc(&parse_callbacks, &cfg, NULL, (void *)json_parser);
#else
	handle = yajl_alloc(&parse_callbacks, NULL, (void *)json_parser);
#endif
	if (handle == NULL) {
		goto fail;
	}
        fdata = malloc(file_stat.st_size + 1);
	if (fdata == NULL) {
		goto fail;
	}
	max_read_len = file_stat.st_size;
	if ((fd = open(file_path, O_RDONLY)) < 0) {
		goto fail;
	}
	while (!finish) {
        	read_len = read(fd, fdata, max_read_len);
                if (read_len < 0) {
			goto fail;
		} else if (read_len == 0) {
#if YAJL_MAJOR <= 1
            		status = yajl_parse_complete(handle);
#else
            		status = yajl_complete_parse(handle);
#endif
			finish = 1;
		} else {
			fdata[read_len] = 0;
            		status = yajl_parse(handle, fdata, read_len);
		}
#if YAJL_MAJOR <= 1
		if (status != yajl_status_ok && status != yajl_status_insufficient_data) {
       			err = yajl_get_error(handle, 1, fdata, read_len);
			LOG(LOG_LV_ERR, "%s\n", err);
			yajl_free_error(handle, err);
			goto fail;
		}
#else
		if (status != yajl_status_ok) {
            		err = yajl_get_error(handle, 1, fdata, read_len);
			LOG(LOG_LV_ERR, "%s\n", err);
			yajl_free_error(handle, err);
			goto fail;
		}
#endif
	}
	json_parser_clean_state_stack(json_parser);
	yajl_free(handle);
	free(fdata);
	close(fd);

	return 0;

fail:
	json_parser_clean_state_stack(json_parser);
	if (handle != NULL) {
		yajl_free(handle);
	}
	free(fdata);
	if (fd != -1) {
		close(fd);
	}

	return 1;

}
