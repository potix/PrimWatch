#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <time.h>

#include "bson/bson.h"

#include "common_macro.h"
#include "common_define.h"
#include "shared_buffer.h"
#include "bson_helper.h"
#include "logger.h"
#include "accessa.h"
#if defined(PRIMDNS)
#include "dns/primdns.h"
#elif defined(POWERDNS)
#include "dns/powerdns.h"
#endif

#if defined(PRIMDNS)
#define PROGIDENT "primwatch_primdns"
#elif defined(POWERDNS)
#define PROGIDENT "primwatch_powerdns"
#endif

#ifndef ACCESSA_DEBUG
#define ACCESSA_DEBUG 0
#endif

static int
accessa_initialize(
    accessa_t *accessa)
{
	int dfopen = 0;
	shared_buffer_t *new_daemon_buffer = NULL;

	ASSERT(accessa != NULL);
	srandom((int)time(NULL) + (int)getpid());
	memset(accessa, 0, sizeof(accessa));
	if (shared_buffer_create(&new_daemon_buffer)) {
		goto fail;
	}
	if (shared_buffer_ropen(new_daemon_buffer, DAEMON_BUFFER_FILE_PATH)) {
		LOG(LOG_LV_ERR, "failed in open daemon buffer");
		goto fail;
	}
	dfopen = 1;
	accessa->daemon_buffer = new_daemon_buffer;

	return 0;

fail:
	if (dfopen) {
		shared_buffer_close(accessa->daemon_buffer);
	}
	if (new_daemon_buffer) {
		shared_buffer_destroy(new_daemon_buffer);
	}

	return 1;
}

static void
accessa_finalize(
    accessa_t *accessa)
{
	ASSERT(accessa != NULL);
	shared_buffer_close(accessa->daemon_buffer);
	shared_buffer_destroy(accessa->daemon_buffer);
}

int
main(int argc, char *argv[]) {
	int ret = EX_OK;
	bson status;
	accessa_t accessa;
	const char *log_type;
	const char *log_facility;
	const char *log_path;
	int64_t verbose_level;
	char *sb_data;
	
	if (logger_create(ACCESSA_DEBUG)) {
		fprintf(stderr, "failed in create logger");
		ret = EX_OSERR;
	}
	if (accessa_initialize(&accessa)) {
		return EX_OSERR;
	}
	if (shared_buffer_read(accessa.daemon_buffer, &sb_data, NULL)) {
		goto last;
	}
	if (bson_init_finished_data(&status, sb_data, 0) != BSON_OK) {
		goto last;
	}
	if (bson_helper_bson_get_string(&status, &log_type , "logType", NULL)) {
		LOG(LOG_LV_ERR, "failed in get log type from status");
		ret = EX_DATAERR;
		goto last;
	}
	if (bson_helper_bson_get_string(&status, &log_facility , "logFacility", NULL)) {
		LOG(LOG_LV_ERR, "failed in get log facility from status");
		ret = EX_DATAERR;
		goto last;
	}
	if (bson_helper_bson_get_string(&status, &log_path , "logPath", NULL)) {
		LOG(LOG_LV_ERR, "failed in get log path from status");
		ret = EX_DATAERR;
		goto last;
	}
	if (bson_helper_bson_get_long(&status, &verbose_level , "verboseLevel", NULL)) {
		LOG(LOG_LV_ERR, "failed in get verbose level from status");
		ret = EX_DATAERR;
		goto last;
	}
	if (logger_open((log_level_t)verbose_level, log_type, PROGIDENT, LOG_PID, log_facility, log_path)) {
		LOG(LOG_LV_ERR, "failed in open log");
		ret = EX_OSERR;
		goto last;
	}
#if defined(PRIMDNS)
	primdns_main(argc, argv, &accessa);
#elif defined(POWERDNS)
	powerdns_loop(&accessa);
#endif
last:
	accessa_finalize(&accessa);
	logger_close();
	logger_destroy();

	return ret;
}
