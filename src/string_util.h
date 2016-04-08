#ifndef STRING_UTIL_H
#define STRING_UTIL_H

#define TUPLE_MAX 32

#if !defined(strlcpy)
#define USE_BSD_STRLCPY
size_t
strlcpy(
    char *dst,
    const char *src,
    size_t siz);
size_t
strlcpylower(
    char *dst,
    const char *src,
    size_t siz);
#endif

#if !defined(strlcat)
#define USE_BSD_STRLCAT
size_t
strlcat(
    char *dst,
    const char *src,
    size_t siz);
#endif

struct kv_split {
	char *key;
	char *value;
};
typedef struct kv_split kv_split_t;

struct tuple_split {
	char *value[TUPLE_MAX];
	int value_count;
};
typedef struct tuple_split tuple_split_t;

struct parse_cmd {
        char *args[NCARGS];
        int arg_size;
};
typedef struct parse_cmd parse_cmd_t;

int string_lstrip_b(
    char **new_str,
    char *str,
    const char *strip_str);

int string_rstrip_b(
    char *str,
    const char *strip_str);

int string_kv_split_b(
    kv_split_t *kv,
    char *str,
    const char *delim_str);

int string_tuple_split_b(
    tuple_split_t *tuple,
    char *str,
    const char *delim_str);

int strtoint(
    int *value,
    const char *str,
    int base);

int strtouc(
    unsigned char *value,
    const char *str,
    int base);

int parse_cmd_b(
    parse_cmd_t *parse_cmd,
    char *cmd);

#endif
