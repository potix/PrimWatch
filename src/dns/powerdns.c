#include <sys/queue.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include "common_macro.h"
#include "accessa.h"
#include "lookup.h"
#include "shared_buffer.h"
#include "logger.h"
#include "dns/powerdns.h"

static void powerdns_output_foreach(void *output_forech_arg, const char *name,
    const char *class, const char *type, unsigned long long ttl, const char *id, const char *content);

void
powerdns_output_foreach(
    void *output_forech_arg,
    const char *name,
    const char *class,
    const char *type,
    unsigned long long ttl,
    const char *id,
    const char *content)
{
	int *abi_version = output_forech_arg;

	ASSERT(abi_version != NULL);

	if (*abi_version == 3) {
		fprintf(stdout, "DATA\t0\t1\t%s\t%s\t%s\t%llu\t%s\t%s\n", name, class, type, ttl, id, content); 
	} else {
		fprintf(stdout, "DATA\t%s\t%s\t%s\t%llu\t%s\t%s\n", name, class, type, ttl, id, content); 
	}
	fflush(stdout);
}

int
powerdns_main(
    const char *qestion,
    const char *qname,
    const char *qclass,
    const char *qtype,
    const char *id,
    const char *remote_ip_address,
    int abi_version,
    accessa_t *accessa)
{
	int lookup_init = 0;
	lookup_t lookup;

	if (lookup_initialize(&lookup, accessa)) {
		LOG(LOG_LV_ERR, "failed in initialize of lookup");
		// log
		goto fail;
	}
	lookup_init = 1;
	if (lookup_setup_input(&lookup, qname, qclass, qtype, id, remote_ip_address, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in setup input");
		// log
		goto fail;
	}
	if (strcasecmp(qestion, "AXFR") == 0) {
		if (lookup_native_axfr(&lookup, powerdns_output_foreach, &abi_version)) {
			LOG(LOG_LV_ERR, "failed in native lookup");
			goto fail;
		}
	} else {
		if (lookup_native(&lookup, powerdns_output_foreach, &abi_version)) {
			LOG(LOG_LV_ERR, "failed in native lookup");
			goto fail;
		}
	}
	if (lookup_finalize(&lookup)) {
		LOG(LOG_LV_ERR, "failed in finalize of lookup");
		// log
		goto fail;
	}
	fprintf(stdout, "END\n");
	fflush(stdout);

	return 0;

fail:
	if (lookup_init) {
		if (lookup_finalize(&lookup)) {
			// log
			goto fail;
		}
	}
	fprintf(stdout, "FAIL\n");
	fflush(stdout);

	return 1;

}
