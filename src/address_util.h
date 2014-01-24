#ifndef ADDR_UTIL_H
#define ADDR_UTIL_H

#include <netinet/in.h>

#define REVADDRSTRLEN 80

typedef enum revfmt_type revfmt_type_t;
typedef union v4v6_in_addr v4v6_in_addr_t;
typedef struct v4v6_addr v4v6_addr_t;
typedef struct v4v6_addr_mask v4v6_addr_mask_t;

enum revfmt_type {
	REVFMT_TYPE_INADDR_ARPA = 1,
	REVFMT_TYPE_IP6_ARPA,
}; 

union v4v6_in_addr {
	struct in_addr sin_addr;
	struct in6_addr sin6_addr;
}; 

struct v4v6_addr {
        unsigned short family;
	v4v6_in_addr_t in_addr;
};

struct v4v6_addr_mask {
	v4v6_addr_t addr;
	int mask;
};

int decrement_mask_b(
    v4v6_addr_mask_t *addr_mask);

int decrement_domain_b(
    char **domain);

int addrstr_to_addrmask_b(
    v4v6_addr_mask_t *addr_mask,
    char *addr_mask_str);

int revaddrstr_to_addrmask_b(
    v4v6_addr_mask_t *addr_mask,
    revfmt_type_t *revfmt_type,
    char *revaddr);

int addrstr_to_addrmask(
    v4v6_addr_mask_t *addr_mask,
    const char *addr_str);

int revaddrstr_to_addrmask(
    v4v6_addr_mask_t *addr_mask,
    revfmt_type_t *revfmt_type,
    const char *revaddr_str);

int addrmask_to_revaddrstr(
    char *revaddr_str,
    size_t revaddr_str_size,
    v4v6_addr_mask_t *addr_mask,
    revfmt_type_t revfmt_type);

#endif
