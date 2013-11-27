#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <logger.h>
#include <limits.h>

#include "common_macro.h"
#include "string_util.h"
#include "address_util.h"

static void
mask_addr(
    v4v6_addr_t *addr,
    int mask)
{
	int i, j;
	int last;
	unsigned char *ptr, m;
	int nomask;

	ASSERT(addr != NULL);
	ASSERT(mask >= 0);
	switch (addr->family) {
	case AF_INET:
		ptr = (unsigned char *)&addr->in_addr.sin_addr;
		last = 4;
		nomask = 32 - mask;
		break;
	case AF_INET6:
		ptr = (unsigned char *)&addr->in_addr.sin6_addr;
		last = 16;
		nomask = 128 - mask;
		break;
	default:
		/* NOTREACHED */
		ABORT("unkown address family");
		break;
	}
	if (nomask == 0) {
		return;
	}
	for (i = last - 1; i >= 0; i--) {
		m = 0x00;
		for (j = 0; j < 8; j++) {
			m |= (0x01 << j);
			nomask--;
			if (nomask == 0) {
				break;
			}
		}
		ptr[i] &= ~m;
		if (nomask == 0) {
			break;
		}
	}
}

int
decrement_mask_b(
    v4v6_addr_mask_t *addr_mask)
{
	if (addr_mask == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (addr_mask->mask == 0) {
		return 1;
	}
	addr_mask->mask--;
	mask_addr(&addr_mask->addr, addr_mask->mask);

	return 0;
}

int
decrement_domain_b(
    char **domain)
{
	const char *origin_domain = *domain;
	char *ptr;
	
	ptr = strchr(origin_domain, '.');
	if (ptr == NULL || *(ptr + 1) == '\0') {
		return 1;	
	}
	*domain = (ptr + 1);

	return 0;
}

int
addrstr_to_addrmask_b(
    v4v6_addr_mask_t *addr_mask,
    char *addr_str)
{
	char *slash;
	char *mask = NULL;
        struct addrinfo addr_info_hints, *addr_info_res, *addr_info_res0 = NULL;
        int err;
	int v;

	if (addr_str == NULL ||
	    addr_mask == NULL) {
		errno = EINVAL;
		return 1;
	}
	memset(addr_mask, 0, sizeof(v4v6_addr_mask_t));
	slash = strchr(addr_str, '/');
	if (slash != NULL) {
		mask = slash + 1;
		*slash = '\0';
	} 
        memset(&addr_info_hints, 0, sizeof(addr_info_hints));
        if ((err = getaddrinfo(addr_str, NULL, &addr_info_hints, &addr_info_res0))) {
                LOG(LOG_LV_ERR, "failed in getaddrinfo (%s : %s)\n", addr_str, gai_strerror(err));
                goto fail;
        }
        for (addr_info_res = addr_info_res0;
             addr_info_res;
             addr_info_res = addr_info_res->ai_next) {
		addr_mask->addr.family = addr_info_res->ai_family;
		switch (addr_mask->addr.family) {
		case AF_INET:
			addr_mask->addr.in_addr.sin_addr = ((struct sockaddr_in *)(addr_info_res->ai_addr))->sin_addr;
			addr_mask->mask = 32;
			break;
		case AF_INET6:
			addr_mask->addr.in_addr.sin6_addr = ((struct sockaddr_in6 *)(addr_info_res->ai_addr))->sin6_addr;
			addr_mask->mask = 128;
			break;
		default:
			LOG(LOG_LV_ERR, "unsupported address family (%d)\n", addr_mask->addr.family);
			return 1;
		}
		if (mask) {
			if (strtoint(&v, mask, 0)) {
				LOG(LOG_LV_ERR, "failed in convert string to integer (%s)\n", mask);
				goto fail;	
			}
			addr_mask->mask = v;
			mask_addr(&addr_mask->addr, addr_mask->mask);
		}
                break;
        }
        freeaddrinfo(addr_info_res0);

	return 0;

fail:
	if (addr_info_res0) {
		freeaddrinfo(addr_info_res0);
	}

	return 1;
}

int
revaddrstr_to_addrmask_b(
    v4v6_addr_mask_t *addr_mask,
    revfmt_type_t *revfmt_type,
    char *revaddr_str)
{
	char *ptr, *end_ptr;
	unsigned char v, tmp;
	unsigned char *a;
	int i, last;

	if (addr_mask == NULL ||
	    revaddr_str == NULL) {
		errno = EINVAL;
		return 1;
	}
	memset(addr_mask, 0, sizeof(v4v6_addr_mask_t));
	if ((ptr = strstr(revaddr_str, "in-addr.arpa")) != NULL) {
		a = (unsigned char *)&addr_mask->addr.in_addr.sin_addr;
		addr_mask->addr.family = AF_INET;
		last = 4 - 1;
		addr_mask->mask = 32;
		if (revfmt_type) {
			*revfmt_type = REVFMT_TYPE_INADDR_ARPA;
		}
	} else if ((ptr = strstr(revaddr_str, "ip6")) != NULL) {
		addr_mask->addr.family = AF_INET6;
		a = (unsigned char *)&addr_mask->addr.in_addr.sin6_addr;
		last = 16 - 1;
		addr_mask->mask = 128;
		if (strstr(ptr, ".arpa") != NULL) {
			if (revfmt_type) {
				*revfmt_type = REVFMT_TYPE_IP6_ARPA;
			}
		} else if (strstr(ptr, ".int") != NULL) {
			if (revfmt_type) {
				*revfmt_type = REVFMT_TYPE_IP6_INT;
			}
		} else {
			LOG(LOG_LV_ERR, "invalid formart (%s)\n", revaddr_str);
			return 1;

		}
	} else {
		LOG(LOG_LV_ERR, "invalid formart (%s)\n", revaddr_str);
		return 1;
	}
	*ptr = '\0';
	ptr = revaddr_str;
	while (*ptr != '\0' && last >= 0) {
		switch (addr_mask->addr.family) {
		case AF_INET:
			end_ptr = strchr(ptr, '.');
			if (end_ptr == NULL) {
				LOG(LOG_LV_ERR, "invalid formart (offset = %d)\n", ptr - revaddr_str);
				return 1;
			}
			*end_ptr = '\0';
			if (strtouc(&v, ptr, 0)) {
				LOG(LOG_LV_ERR, "failed in convert string to unsigned char (%s)\n", ptr);
				return 1;	
			}
			ptr = end_ptr + 1;
			a[last--] = v;
			break;
		case AF_INET6:
			 v = 0;
			for (i = 0; i < 2; i ++) {
                                if (*ptr == '\0') {
					LOG(LOG_LV_ERR, "invalid formart (offset = %d)\n", ptr - revaddr_str);
					return 1;
				}
				end_ptr = strchr(ptr, '.');
				if (end_ptr == NULL) {
					LOG(LOG_LV_ERR, "invalid formart (offset = %d)\n", ptr - revaddr_str);
					return 1;
				}
				*end_ptr = '\0';
				if (strtouc(&tmp, ptr, 16)) {
					LOG(LOG_LV_ERR, "failed in convert string to unsigned char (%s)\n", ptr);
					return 1;	
				}
				ptr = end_ptr + 1;
				if (i == 1) {
					tmp = tmp << 4;
				}
				v |= tmp;
			}
			a[last--] = v;
			break;
		default:
			/* NOTREACHED */
			ABORT("unkown address family");
			return 1;
		}
	}
	if (last != -1) {
		LOG(LOG_LV_ERR, "invalid formart (offset = %d)\n", ptr - revaddr_str);
		return 1;
	}

	return 0;
}

int
addrstr_to_addrmask(
    v4v6_addr_mask_t *addr_mask,
    const char *addr_str)
{
	char copy_addr_str[INET6_ADDRSTRLEN + 4];

	strlcpy(copy_addr_str, addr_str, sizeof(copy_addr_str));
	return addrstr_to_addrmask_b(addr_mask, copy_addr_str);
}

int
revaddrstr_to_addrmask(
    v4v6_addr_mask_t *addr_mask,
    revfmt_type_t *revfmt_type,
    const char *revaddr_str)
{
	char copy_revaddr_str[REVADDRSTRLEN];

	strlcpy(copy_revaddr_str, revaddr_str, sizeof(copy_revaddr_str));
	return revaddrstr_to_addrmask_b(addr_mask, revfmt_type, copy_revaddr_str);
}

int
addrmask_to_revaddrstr(
    char *revaddr_str,
    size_t revaddr_str_size,
    v4v6_addr_mask_t *addr_mask,
    revfmt_type_t revfmt_type)
{
	int i;
	const char *suffix;
	char tmp[8];
	unsigned char *ptr, vh, vl;

	if (revaddr_str == NULL ||
	    revaddr_str_size < 1 ||
	    addr_mask == NULL ||
	    revfmt_type == 0) {
		errno = EINVAL;
		return 1;
	}
	revaddr_str[0] = '\0';
	switch (addr_mask->addr.family) {
	case AF_INET:
		switch (revfmt_type) {
		case REVFMT_TYPE_INADDR_ARPA:
			suffix = "in-addr.arpa";
			break;
		default:
			errno = EINVAL;
			return 1;
		}
		for (i = 3; i >= 0; i--) {
			ptr = (unsigned char *)&addr_mask->addr.in_addr.sin_addr;
			snprintf(tmp, sizeof(tmp), "%d.", ptr[i]);
			strlcat(revaddr_str, tmp, revaddr_str_size);
		}
		strlcat(revaddr_str, suffix, revaddr_str_size);
		break;
	case AF_INET6:
		switch (revfmt_type) {
		case REVFMT_TYPE_IP6_ARPA:
			suffix = "ip6.arpa";
			break;
		case REVFMT_TYPE_IP6_INT:
			suffix = "ip6.int";
			break;
		default:
			errno = EINVAL;
			return 1;
		}
		for (i = 15; i >= 0; i--) {
			ptr = (unsigned char *)&addr_mask->addr.in_addr.sin6_addr;
			vh = ptr[i] >> 4;
			vl = ptr[i] & 0x0f;
			snprintf(tmp, sizeof(tmp), "%x.", vl);
			strlcat(revaddr_str, tmp, revaddr_str_size);
			snprintf(tmp, sizeof(tmp), "%x.", vh);
			strlcat(revaddr_str, tmp, revaddr_str_size);
		}
		strlcat(revaddr_str, suffix, revaddr_str_size);
		break;
	default:
		errno = EINVAL;
		return 1;
	}

	return 0;
}

