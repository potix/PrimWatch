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
	int dbufopen = 0;
	int abufopen = 0;
	int dbuflockmap = 0;
	shared_buffer_t *new_daemon_buffer = NULL;
	shared_buffer_t *new_accessa_buffer = NULL;

	ASSERT(accessa != NULL);
	srandom((int)time(NULL) + (int)getpid());
	memset(accessa, 0, sizeof(accessa));
	if (shared_buffer_create(&new_daemon_buffer)) {
		LOG(LOG_LV_ERR, "failed in create shared buffer of daemon");
		goto fail;
	}
	if (shared_buffer_create(&new_accessa_buffer)) {
		LOG(LOG_LV_ERR, "failed in create shared buffer of accessa");
		goto fail;
	}
	if (shared_buffer_open(new_daemon_buffer, DAEMON_BUFFER_FILE_PATH, SHBUF_OFL_READ)) {
		LOG(LOG_LV_ERR, "failed in open shared buffer of daemon");
		goto fail;
	}
	dbufopen = 1;
	if (shared_buffer_open(new_accessa_buffer, ACCESSA_BUFFER_FILE_PATH, SHBUF_OFL_READ|SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "failed in open shared buffer of accessa");
		goto fail;
	}
	abufopen = 1;
	if (shared_buffer_lock_map(new_daemon_buffer, 0)) {
		LOG(LOG_LV_ERR, "failed in lock and map of shared buffer of daemon");
		goto fail;
        } 
	dbuflockmap = 1;
	accessa->daemon_buffer = new_daemon_buffer;
	accessa->accessa_buffer = new_accessa_buffer;

	return 0;

fail:
	if (dbuflockmap) {
		shared_buffer_unlock_unmap(new_daemon_buffer);
	}
	if (dbufopen) {
		shared_buffer_close(new_daemon_buffer);
	}
	if (abufopen) {
		shared_buffer_close(new_accessa_buffer);
	}
	if (new_daemon_buffer) {
		shared_buffer_destroy(new_daemon_buffer);
	}
	if (new_accessa_buffer) {
		shared_buffer_destroy(new_accessa_buffer);
	}

	return 1;
}

static void
accessa_finalize(
    accessa_t *accessa)
{
	ASSERT(accessa != NULL);
	if (accessa->daemon_buffer) {
		shared_buffer_unlock_unmap(accessa->daemon_buffer);
		shared_buffer_close(accessa->daemon_buffer);
		shared_buffer_destroy(accessa->daemon_buffer);
	}
	if (accessa->accessa_buffer) {
		shared_buffer_close(accessa->accessa_buffer);
		shared_buffer_destroy(accessa->accessa_buffer);
	}
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
	
	if (logger_create()) {
		fprintf(stderr, "failed in create logger");
		ret = EX_OSERR;
	}
	if (logger_set_foreground(ACCESSA_DEBUG)) {
		fprintf(stderr, "failed in set foreground");
		ret = EX_OSERR;
	}
	if (accessa_initialize(&accessa)) {
		return EX_OSERR;
	}
	if (shared_buffer_read(accessa.daemon_buffer, &sb_data, NULL)) {
		LOG(LOG_LV_WARNING, "failed in read daemon buffer");
		goto last;
	}
	if (sb_data == NULL) {
		LOG(LOG_LV_WARNING, "daemon buffer is empty");
		goto last;
	}
	if (bson_init_finished_data(&status, sb_data, 0) != BSON_OK) {
		LOG(LOG_LV_WARNING, "failed in ");
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
