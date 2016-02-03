#include <sys/queue.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include "accessa.h"
#include "lookup.h"
#include "shared_buffer.h"
#include "logger.h"
#include "dns/primdns.h"

#define NOERROR  "0"
#define FORMERR  "1"
#define SERVFAIL "2"
#define NXDOMAIN "3"
#define NOTIMP   "4"
#define REFUSED  "5"
#define YXDOMAIN "6"
#define YXRRSET  "7"
#define NXRRSET  "8"
#define NOTAUTH  "9"
#define NOTZONE  "10"

static void primdns_output_foreach(void *output_forech_arg, const char *name,
    const char *class, const char *type, unsigned long long ttl, const char *id, const char *content);

struct output_buffer {
	char buf[65535];
	int len;
};
typedef struct output_buffer output_buffer_t;

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
	output_buffer_t *output_buffer = output_forech_arg;
	output_buffer->len += snprintf(&output_buffer->buf[output_buffer->len], sizeof(output_buffer->buf) - output_buffer->len, "%s %llu %s %s %s\n", name, ttl, class, type, content); 
}

int
primdns_main(
    int argc,
    char **argv,
    accessa_t *accessa)
{
	int lookup_init = 0;
	lookup_t lookup;
	output_buffer_t output_buffer = { .len= 0 };

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
	if (lookup_native(&lookup, primdns_output_foreach, &output_buffer)) {
		LOG(LOG_LV_ERR, "failed in native lookup");
		goto fail;
	}
	if (lookup.output.entry_count == 0) {
		if (lookup_record_is_exists(&lookup)) {
			printf("%s\n", NOERROR);
		} else {
			printf("%s\n", NXDOMAIN);
		}
	} else {
		printf("%s\n", NOERROR);
	}
	printf("%s", output_buffer.buf);
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
