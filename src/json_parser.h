#ifndef JSON_PARSER_H 
#define JSON_PARSER_H 

#include "bson.h"

#ifndef MAX_JSON_PATH_LEN
#define MAX_JSON_PATH_LEN 2046
#endif
#define JSON_PARSER_VALIDATION_SUCCESS 0 
#define JSON_PARSER_VALIDATION_ERROR 1

typedef struct json_parser json_parser_t;

int json_parser_create(
    json_parser_t **json_parser);

int json_parser_destroy(
    json_parser_t *json_parser);

int json_parser_add_validation_boolean(
    json_parser_t *json_parser,
    const char *regex_path,
    int (*validate_callback)(
        void *validate_callback_arg,
        const char *path,
        const char *key,
        int b,
        bson *bson),
    void *validate_callback_arg);

int json_parser_add_validation_integer(
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
    void *validate_callback_arg);

int json_parser_add_validation_double(
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
    void *validate_callback_arg);

int json_parser_add_validation_string(
    json_parser_t *json_parser,
    const char *regex_path,
    size_t minlen,
    size_t maxlen,
    const char *candidate[],
    int ncandidate,
    int (*validate_callback)(
        void *validate_callback_arg,
        const char *path,
        const char *key,
        const char *s,
        size_t len,
        bson *bson),
    void *validate_callback_arg);

int json_parser_parse(
    json_parser_t *json_parser,
    const char *file_path,
    bson *bson);

#endif

