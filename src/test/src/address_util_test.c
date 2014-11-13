#include <sys/param.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_macro.h"
#include "logger.h"
#include "string_util.h"
#include "address_util.h"

int
main(int argc, char*argv[])
{
	v4v6_addr_mask_t addr_mask;
	revfmt_type_t type;
	char str[128];

        ASSERT(logger_create() == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "10.0.0.1") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 32);
        ASSERT(strcmp(str, "10.0.0.1") == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "2001::1") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 128);
        ASSERT(strcmp(str, "2001::1") == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "10.6.7.0/24") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 24);
        ASSERT(strcmp(str, "10.6.7.0") == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "2001:10::0/64") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 64);
        ASSERT(strcmp(str, "2001:10::") == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "10.0.5.4/16") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 16);
        ASSERT(strcmp(str, "10.0.0.0") == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "2001:10::10:5/32") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 32);
        ASSERT(strcmp(str, "2001:10::") == 0);
	ASSERT(addrstr_to_addrmask(&addr_mask, "1.1.1.3/32") == 0);
        ASSERT(addr_mask.mask == 32);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1.1.1.3") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 31);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1.1.1.2") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 30);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1.1.1.0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 24);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1.1.1.0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 16);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1.1.0.0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 8);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1.0.0.0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "0.0.0.0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 1);
	ASSERT(addrstr_to_addrmask(&addr_mask, "1:1:1:1:1:1:1:3/128") == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(addr_mask.mask == 128);
        ASSERT(strcmp(str, "1:1:1:1:1:1:1:3") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 127);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1:1:1:1:1:2") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 126);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1:1:1:1:1:0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 112);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1:1:1:1:1:0") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 96);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1:1:1:1::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 80);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1:1:1::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 64);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1:1::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 48);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1:1::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 32);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1:1::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 16);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "1::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 0);
        ASSERT(addr_mask.mask == 0);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "::") == 0);
        ASSERT(decrement_mask_b(&addr_mask) == 1);
	ASSERT(revaddrstr_to_addrmask(&addr_mask, &type, "1.1.1.10.in-addr.arpa") == 0);
	ASSERT(type == REVFMT_TYPE_INADDR_ARPA);
        ASSERT(addr_mask.mask == 32);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "10.1.1.1") == 0);
        ASSERT(addrmask_to_revaddrstr(str, sizeof(str), &addr_mask, type) == 0);
	ASSERT(strcmp(str, "1.1.1.10.in-addr.arpa") == 0);
	ASSERT(revaddrstr_to_addrmask(&addr_mask, &type, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa") == 0);
	ASSERT(type == REVFMT_TYPE_IP6_ARPA);
        ASSERT(addr_mask.mask == 128);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "2001::1") == 0);
        ASSERT(addrmask_to_revaddrstr(str, sizeof(str), &addr_mask, type) == 0);
	ASSERT(strcmp(str, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa") == 0);
	ASSERT(revaddrstr_to_addrmask(&addr_mask, &type, "1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.2.ip6.arpa") == 0);
	ASSERT(type == REVFMT_TYPE_IP6_ARPA);
        ASSERT(addr_mask.mask == 128);
        ASSERT(inet_ntop(addr_mask.addr.family, &addr_mask.addr.in_addr, str, sizeof(str)) != NULL);
        ASSERT(strcmp(str, "2002::11") == 0);
        ASSERT(addrmask_to_revaddrstr(str, sizeof(str), &addr_mask, type) == 0);
	ASSERT(strcmp(str, "1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.2.ip6.arpa") == 0);

	return 0;
}
