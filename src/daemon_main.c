#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>
#include <errno.h>
#include <sysexits.h>
#include <event.h>
#include <fcntl.h>

#include "common_macro.h"
#include "common_define.h"
#include "string_util.h"
#include "config_manager.h"
#include "watcher.h"
#include "controller.h"
#include "logger.h"

#ifndef DEFAULT_PRIMWATCH_CONFIG_FILE_PATH 
#define DEFAULT_PRIMWATCH_CONFIG_FILE_PATH "/etc/primwatch.conf"
#endif
#ifndef PROGIDENT
#define PROGIDENT "primwatchd"
#endif

typedef struct primwatch primwatch_t;

struct primwatch {
	struct event_base *event_base;
	struct event sig_term_event;
	struct event sig_int_event;
	struct event sig_hup_event;
	struct event sig_chld_event;
	int foreground;
	const char *config_file;
	watcher_t *watcher;
	controller_t *controller;
	config_manager_t *config_manager;
};

static int primwatch_initialize(primwatch_t *primwatch);
static int primwatch_event_initialize(primwatch_t *primwatch);
static void primwatch_finalize(primwatch_t *primwatch);
static void primwatch_terminate(int fd, short event, void *args);
static void primwatch_reload(int fd, short event, void *args);
static void primwatch_sigchild(int fd, short event, void *args);
static void usage(char *argv0);
static void parse_args(primwatch_t *primwatch, int argc, char **argv);
static int make_pidfile(const char *pid_file);

static int
primwatch_initialize(
    primwatch_t *primwatch)
{
        ASSERT(primwatch != NULL);
	memset(primwatch, 0, sizeof(primwatch_t));
	primwatch->config_file = DEFAULT_PRIMWATCH_CONFIG_FILE_PATH;
	if (config_manager_create(&primwatch->config_manager)) {
		fprintf(stderr, "can not create config instance\n");
		return 1;
	} 

	return 0;
}

static int
primwatch_event_initialize(
    primwatch_t *primwatch)
{
	if ((primwatch->event_base = event_init()) == NULL) {
		fprintf(stderr, "can not create event cntext\n");
		return 1;
	}
	if (event_base_priority_init(primwatch->event_base, DEFAULT_EVENT_PRIORITY)) {
		fprintf(stderr, "can not initialize event priority\n");
		return 1;
	}
	if (watcher_create(
            &primwatch->watcher,
            primwatch->event_base,
            primwatch->config_manager)) {
		fprintf(stderr, "can not create wathcer instance\n");
		return 1;
	} 
	if (controller_create(
            &primwatch->controller,
            primwatch->event_base,
	    primwatch->watcher)) {
		fprintf(stderr, "can not create controller instance\n");
		return 1;
	} 

	return 0;
}

static void
primwatch_finalize(
    primwatch_t *primwatch)
{
	if (primwatch->controller) {
		controller_destroy(primwatch->controller);
	}
	if (primwatch->watcher) {
		watcher_destroy(primwatch->watcher);
	}
	if (primwatch->config_manager) {
		config_manager_destroy(primwatch->config_manager);
	}
	if (primwatch->event_base) {
		event_base_free(primwatch->event_base);
	}
}

static void
primwatch_terminate(
    int fd,
    short event,
    void *args)
{
	primwatch_t *primwatch = args;

	if (controller_stop(primwatch->controller)) {
		LOG(LOG_LV_WARNING, "failed in stop controller");
	}
	if (watcher_polling_stop(primwatch->watcher)) {
		LOG(LOG_LV_WARNING, "failed in stop polling");
	}
     	signal_del(&primwatch->sig_chld_event);
     	signal_del(&primwatch->sig_int_event);
     	signal_del(&primwatch->sig_term_event);
     	signal_del(&primwatch->sig_hup_event);
}

static void
primwatch_reload(
    int fd,
    short event,
    void *args)
{
	primwatch_t *primwatch = args;

	if (config_manager_load(primwatch->config_manager, primwatch->config_file)) {
		LOG(LOG_LV_ERR, "failed in load config manager");
	}
}

static void
primwatch_sigchild(
    int fd,
    short event,
    void *args)
{
	primwatch_t *primwatch = args;

	watcher_sigchild(primwatch->watcher);
}

static void
usage(
    char *argv0)
{
        char cmd_path[MAXPATHLEN], *cmd;
        strlcpy(cmd_path, argv0, sizeof(cmd_path));
        cmd = basename(cmd_path);
	printf("usage: %s [-c <config_file>] [-F] [-h]\n", cmd);
	exit(EX_USAGE);
}

static void
parse_args(
    primwatch_t *primwatch,
    int argc,
    char **argv)
{
        int opt;

        ASSERT(primwatch != NULL);
        ASSERT(argv != NULL);
        while ((opt = getopt(argc, argv, "c:Fh")) != -1) {
                switch (opt) {
                case 'c':
                        primwatch->config_file = optarg;
                        break;
                case 'F':
                        primwatch->foreground = 1;
                        break;
                case 'h':
                        usage(argv[0]);
                default:
                        usage(argv[0]);
                }
        }
}

static int 
make_pidfile(
    const char *pid_file)
{
	int fd = -1;
	char pid[32];
	int len;

	fd = open(pid_file, O_RDWR|O_CREAT|O_TRUNC|O_EXCL, 0644);
	if (fd < 0) {
		if (errno == EEXIST) {
			LOG(LOG_LV_ERR, "already exist process\n");
			return 1;
		}
		LOG(LOG_LV_ERR, "fail in create pidfile (%m)\n");
		return 1;
	}
	len = snprintf(pid, sizeof(pid), "%d", getpid());
	if (ftruncate(fd, len)) {
		LOG(LOG_LV_ERR, "fail in truncate (%m)\n");
		return 1;
       	}
	write(fd, pid, len);
	close(fd); 

	return 0;
}

int
main(int argc, char *argv[]) {
	int ret = EX_OK;
	primwatch_t primwatch;
	const char *log_type;
	const char *log_facility;
	const char *log_path;
	const char *pid_file_path;
	const char *cntrl_addr;
	const char *cntrl_port;
	int64_t verbose_level;

	if (logger_create()) {
		fprintf(stderr, "failed in create logger");
		ret = EX_OSERR;
	}
	if (primwatch_initialize(&primwatch)) {
		fprintf(stderr, "failed in initaizliae");
		ret = EX_OSERR;
		goto last;
	}
	parse_args(&primwatch, argc, argv);
	if (logger_set_foreground(primwatch.foreground)) {
		fprintf(stderr, "failed in create logger");
		ret = EX_OSERR;
	}
	if (config_manager_load(primwatch.config_manager, primwatch.config_file)) {
		LOG(LOG_LV_ERR, "failed in load config file %s", primwatch.config_file);
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_string(primwatch.config_manager, &log_type , "logType", NULL)) {
		LOG(LOG_LV_ERR, "failed in get log type from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_string(primwatch.config_manager, &log_facility , "logFacility", NULL)) {
		LOG(LOG_LV_ERR, "failed in get log facility from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_string(primwatch.config_manager, &log_path , "logPath", NULL)) {
		LOG(LOG_LV_ERR, "failed in get log path from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_string(primwatch.config_manager, &pid_file_path , "pidFilePath", NULL)) {
		LOG(LOG_LV_ERR, "failed in get pid file path from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_string(primwatch.config_manager, &cntrl_addr , "controllerAddress", NULL)) {
		LOG(LOG_LV_ERR, "failed in get controller address from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_string(primwatch.config_manager, &cntrl_port , "controllerPort", NULL)) {
		LOG(LOG_LV_ERR, "failed in get controller port from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (config_manager_get_long(primwatch.config_manager, &verbose_level , "verboseLevel", NULL)) {
		LOG(LOG_LV_ERR, "failed in get verbose level from config");
		ret = EX_DATAERR;
		goto last;
	}
	if (logger_open((log_level_t)verbose_level, log_type, PROGIDENT, LOG_PID, log_facility, log_path)) {
		LOG(LOG_LV_ERR, "failed in open log");
		ret = EX_OSERR;
		goto last;
	}
        if (!primwatch.foreground) {
		if (daemon(1,1)) {
			LOG(LOG_LV_ERR, "failed in daemon");
			ret = EX_OSERR;
			goto last;
		}
		setsid();
	}
	if (primwatch_event_initialize(&primwatch)) {
		fprintf(stderr, "failed in initaizliae");
		ret = EX_OSERR;
		goto last;
	}
	if (make_pidfile(pid_file_path)) {
		LOG(LOG_LV_ERR, "failed in create file of process id");
		ret = EX_OSERR;
		goto last;
	}
	if (watcher_polling_start(primwatch.watcher)) {
		LOG(LOG_LV_ERR, "failed in initial polling");
		ret = EX_OSERR;
		goto last;
	}
	if (controller_start(primwatch.controller, cntrl_addr, cntrl_port)) {
		LOG(LOG_LV_ERR, "failed in start controller");
		ret = EX_OSERR;
		goto last;
	}
	signal_set(&primwatch.sig_int_event, SIGINT, primwatch_terminate, &primwatch);
	event_priority_set(&primwatch.sig_int_event, DEFAULT_EVENT_PRIORITY + 30);
	event_base_set(primwatch.event_base, &primwatch.sig_int_event);
	signal_add(&primwatch.sig_int_event, NULL);
	signal_set(&primwatch.sig_term_event, SIGTERM, primwatch_terminate, &primwatch);
	event_priority_set(&primwatch.sig_term_event, DEFAULT_EVENT_PRIORITY + 30);
	event_base_set(primwatch.event_base, &primwatch.sig_term_event);
	signal_add(&primwatch.sig_term_event, NULL);
	signal_set(&primwatch.sig_hup_event, SIGHUP, primwatch_reload, &primwatch);
	event_priority_set(&primwatch.sig_hup_event, DEFAULT_EVENT_PRIORITY + 30);
	event_base_set(primwatch.event_base, &primwatch.sig_hup_event);
	signal_add(&primwatch.sig_hup_event, NULL);
	signal_set(&primwatch.sig_chld_event, SIGCHLD, primwatch_sigchild, &primwatch);
	event_priority_set(&primwatch.sig_chld_event, DEFAULT_EVENT_PRIORITY + 30);
	event_base_set(primwatch.event_base, &primwatch.sig_chld_event);
	signal_add(&primwatch.sig_chld_event, NULL);
	if (event_base_dispatch(primwatch.event_base) == -1) {
		LOG(LOG_LV_ERR, "failed in event base dispatch");
		ret = EX_OSERR;
		goto last;
	}
last:
	unlink(pid_file_path);
	logger_close();
	logger_destroy();
	primwatch_finalize(&primwatch);

	return ret;
}
