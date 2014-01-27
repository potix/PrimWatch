#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>

#include "accessa.h"
#include "lookup.h"
#include "shared_buffer.h"
#include "logger.h"
#include "dns/primdns.h"

#define NOERROR  "0"
#define NXDOMAIN "3"

void
primdns_output_foreach(
    void *output_forech_arg,
    const char *name,
    const char *class,
    const char *type,
    unsigned long long ttl,
    const char *id,
    const char *content)
{
	printf("%s %llu %s %s %s\n", name, ttl, class, type, content); 
}

int
primdns_main(
    int argc,
    char **argv,
    accessa_t *accessa)
{
	int lookup_init = 0;
	lookup_t lookup;

	if (argc < 4) {
		LOG(LOG_LV_ERR, "too few arguments");
		// log
		goto fail;
	}
	if (lookup_initialize(&lookup, accessa)) {
		LOG(LOG_LV_ERR, "failed in initialize of lookup");
		// log
		goto fail;
	}
	lookup_init = 1;
	if (lookup_setup_input(&lookup, argv[1], argv[2], argv[3], NULL, NULL, NULL, NULL)) {
		LOG(LOG_LV_ERR, "failed in setup input");
		// log
		goto fail;
	}
	if (lookup_native(&lookup, primdns_output_foreach, NULL)) {
		LOG(LOG_LV_ERR, "failed in native lookup");
		goto fail;
	}
	printf("%s\n", NOERROR);
	if (lookup_finalize(&lookup)) {
		LOG(LOG_LV_ERR, "failed in finalize of lookup");
		// log
		goto fail;
	}

	return 0;

fail:
	if (lookup_init) {
		if (lookup_finalize(&lookup)) {
			// log
			goto fail;
		}
	}
	printf("%s\n", NXDOMAIN);

	return 1;

}
