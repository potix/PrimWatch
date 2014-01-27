#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#include "common_macro.h"
#include "logger.h"

#if defined(__linux__) && defined(__USE_LARGEFILE64)
#define FOPEN fopen64
#else
#define FOPEN fopen
#endif

#define DEFAULT_LOG_FACILITY    LOG_LOCAL1
#define DEFAULT_VERBOSE_LEVEL   LOG_INFO
#define VERBOSE_LEVEL_ALL       (LOG_MAX - 1)

#define LOG_PREFIX_BUFF         32
#define LOG_TIME_BUFF           64
#define LOG_HEAD_BUFF           128
#define LOG_MESG_BUFF           512
#define LOG_DUMP_BUFF           256

enum log_state {
        LOG_ST_NONE     = 0,
        LOG_ST_INIT     = 1,
        LOG_ST_OPENED   = 2,
        LOG_ST_CLOSED   = 3,
};
typedef enum log_state log_state_t;

enum log_type {
        LOG_TYPE_VALUE_STDOUT = 0,
        LOG_TYPE_VALUE_STDERR = 1,
        LOG_TYPE_VALUE_SYSLOG = 2,
        LOG_TYPE_VALUE_FILE   = 3,
};
typedef enum log_type log_type_t;

struct logger{
        int log_state;
        log_level_t verbose_level;
        int log_type;
        FILE *log;
        struct tm log_time;
        char *logfilename;
        pid_t pid;
        unsigned long long log_seq;
	int foreground;
};
typedef struct logger logger_t;

static const char logger_tag_map[LOG_LV_MAX][LOG_PREFIX_BUFF] = {
	"[UNKOWN]",	/* 0 */
	"[EMERG]",	/* 1 */
	"[ALERT]",	/* 2 */
	"[CRIT]",	/* 3 */
	"[ERROR]",	/* 4 */
	"[WARNING]",	/* 5 */
	"[NOTICE]",	/* 6 */
	"[INFO]",	/* 7 */
	"[DEBUG]",	/* 8 */
	"[TRACE]",	/* 9 */
};

int log_level_map[LOG_LV_MAX] = {
	LOG_EMERG,   /* LOG_LV_EMERG */
	LOG_ALERT,   /* LOG_LV_ALERT */
	LOG_CRIT,    /* LOG_LV_CRIT */
	LOG_ERR,     /* LOG_LV_ERR */
	LOG_WARNING, /* LOG_LV_WARNING */
	LOG_NOTICE,  /* LOG_LV_NOTICE */
	LOG_INFO,    /* LOG_LV_INFO */
	LOG_DEBUG,   /* LOG_LV_DEBUG */
	LOG_DEBUG    /* LOG_LV_TRACE */
};

logger_t *g_logger;

static int
logger_get_facility(
    const char *facility)
{
	if (facility == NULL) {
		return DEFAULT_LOG_FACILITY;
	}
	if (strcasecmp(facility, LOG_FAC_DAEMON) == 0) {
		return LOG_DAEMON;
	} else if (strcasecmp(facility, LOG_FAC_USER) == 0) {
		return LOG_USER;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL0) == 0) {
		return LOG_LOCAL0;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL1) == 0) {
		return LOG_LOCAL1;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL2) == 0) {
		return LOG_LOCAL2;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL3) == 0) {
		return LOG_LOCAL3;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL4) == 0) {
		return LOG_LOCAL4;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL5) == 0) {
		return LOG_LOCAL5;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL6) == 0) {
		return LOG_LOCAL6;
	} else if (strcasecmp(facility, LOG_FAC_LOCAL7) == 0) {
		return LOG_LOCAL7;
	} else {
		return DEFAULT_LOG_FACILITY;
	}
}

static void
logger_syslog_open(
    const char *ident,
    int option,
    const char *facility)
{
	int fac;
	const char *l_ident;

	l_ident = ident;
	fac = logger_get_facility(facility);
	openlog(l_ident, option|LOG_PID, fac);
}

static int
logger_get_mtime(
    const char *filename,
    time_t *m_time)
{
	struct stat sb;

	if (stat(filename, &sb)) {
		return 1;
	}
	*m_time = sb.st_mtime;

	return 0;
}

static int
logger_is_need_rotate(
    struct tm *cur_tm,
    struct tm *m_tm)
{
	if (cur_tm->tm_mday != m_tm->tm_mday ||
	    cur_tm->tm_mon != m_tm->tm_mon ||
	    cur_tm->tm_year != m_tm->tm_year) {
		return 1;
	}

	return 0;
}

static int
logger_get_rotatelogger_filename(
    char *filename,
    size_t filename_len,
    const char *prefix,
    struct tm *m_tm)
{
	snprintf(
	    filename,
	    filename_len,
	    "%s.%04d-%02d-%02d",
	    prefix,
	    (m_tm->tm_year + 1900),
	    (m_tm->tm_mon + 1),
	    (m_tm->tm_mday));
	return 0;
}

static int
logger_rotate(
    struct tm *cur_tm)
{
	char filename[MAXPATHLEN];
	char filename_rotate[MAXPATHLEN];
	FILE *fp;

	if (g_logger->log_type != LOG_TYPE_VALUE_FILE) {
		return 0;
	}
	snprintf(filename, sizeof(filename), "%s", g_logger->logfilename);
	if (g_logger->log_state == LOG_ST_OPENED) {
		ASSERT(g_logger->log != NULL);
		if (logger_is_need_rotate(cur_tm, &g_logger->log_time)) {
			/* need rotate */
			logger_get_rotatelogger_filename(
			    filename_rotate,
			    sizeof(filename_rotate),
			    g_logger->logfilename,
			    &g_logger->log_time);
			fclose(g_logger->log);
			g_logger->log = NULL;
			g_logger->log_state = LOG_ST_CLOSED;
			if (rename(filename, filename_rotate)) {
				fprintf(
				    stderr,
				    "(%d) [ERROR] can not rename log file (%s -> %s)\n",
				    g_logger->pid,
				    filename,
				    filename_rotate);
			}
			fp = FOPEN(filename, "a+");
			if (fp == NULL) {
				fprintf(
				    stderr,
				    "(%d) [ERROR] can not open log file (%s)\n",
				    g_logger->pid,
				    filename);
				return 1;
			}
			g_logger->log_state = LOG_ST_OPENED;
			g_logger->log = fp;
		}
	} else {
		ASSERT(g_logger->log == NULL);
		fp = FOPEN(filename, "a+");
		if (fp == NULL) {
			fprintf(
			    stderr,
			    "(%d) [ERROR] can not open log file (%s)\n",
			    g_logger->pid,
			    filename);
			return 1;
		}
		g_logger->log_state = LOG_ST_OPENED;
		g_logger->log = fp;
	}

        return 0;
}

static int
logger_file_open(
    const char *logfile)
{
	time_t cur_time;
	time_t m_time;
        struct tm cur_tm;
        struct tm m_tm;
	const char *l_logfile;
        char filename[MAXPATHLEN];
        char filename_rotate[MAXPATHLEN];

	if (logfile == NULL) {
		fprintf(stderr,
		     "(%d) [ERROR] invalid log file path (%s)\n",
		     g_logger->pid,
		     logfile);
		return 1;
	} else {
		l_logfile = logfile;
	}
        snprintf(filename, sizeof(filename), "%s", l_logfile);
	cur_time = time(NULL);
	localtime_r(&cur_time, &cur_tm);

	if (logger_get_mtime(filename, &m_time) == 0) {
		localtime_r(&m_time, &m_tm);
		if (logger_is_need_rotate(&cur_tm, &m_tm)) {
			/* need rotate */
			logger_get_rotatelogger_filename(
			    filename_rotate,
			    sizeof(filename_rotate),
			    l_logfile,
			    &m_tm);
			if(rename(filename, filename_rotate)) {
				fprintf(
				    stderr,
				    "(%d) [ERROR] can not rename log file (%s -> %s)\n",
				    g_logger->pid,
				    filename,
				    filename_rotate);
			}
		}
	}
	g_logger->log = FOPEN(filename, "a+");
	if (g_logger->log == NULL) {
		fprintf(
		    stderr,
		    "(%d) [ERROR] can not open log file (%s)\n",
		    g_logger->pid,
		    filename);
		return 1;
	}
	g_logger->log_time = cur_tm;

	return 0;
}

static const char *
logger_get_log_tag(
    log_level_t level)
{
	if (level < 0 || level >= LOG_LV_MAX) {
		return logger_tag_map[LOG_INFO];
	}

	return logger_tag_map[level];
}

static int
logger_get_log_level(
    log_level_t level)
{
	if (level < 0 || level >= LOG_LV_MAX) {
		return LOG_INFO;
	}

	return log_level_map[level];
}

static int
logging_base(
    FILE *fp,
    log_level_t level,
    log_type_t type,
    const char *name,
    const char *fmt,
    va_list ap,
    struct tm *tm)
{
	char logtime[LOG_TIME_BUFF];
	char loghead[LOG_HEAD_BUFF];
	char logmesg[LOG_MESG_BUFF];
	const char *log_fmt;

	ASSERT(g_logger != NULL);
	if (level > g_logger->verbose_level) {
		return 0;
	}
	vsnprintf(logmesg, sizeof(logmesg), fmt, ap);
	strftime(logtime, sizeof(logtime), "LOG\t%Y/%m/%d %H:%M:%S", tm);
	snprintf(
	    loghead,
	    sizeof(loghead),
	    "{%llu} (%d) %s %s:",
	    g_logger->log_seq,
	    g_logger->pid,
	    logger_get_log_tag(level),
            name);
	log_fmt = (g_logger->verbose_level >= LOG_LV_DEBUG) ? "%s %s %s (%m)\n": "%s %s %s\n";
	if (type == LOG_TYPE_VALUE_SYSLOG) {
		syslog(
		    logger_get_log_level(level),
		    log_fmt,
		    logtime,
		    loghead,
		    logmesg);
	} else {
		fprintf(fp, log_fmt, logtime, loghead, logmesg);
	}
	if ((type == LOG_TYPE_VALUE_SYSLOG || type == LOG_TYPE_VALUE_FILE)
	    && g_logger->foreground) {
		fprintf(stdout, log_fmt, logtime, loghead, logmesg);
	}
	g_logger->log_time = *tm;
	g_logger->log_seq++;

	return 0;
}

int
logging(
    log_level_t level,
    const char *name,
    const char *fmt,
    ...)
{
	FILE *fp;
	va_list ap;
	time_t t;
	struct tm tm;

	ASSERT(g_logger != NULL);
	if (fmt == NULL || *fmt == '\0' ) {
		fprintf(
		    stderr,
		    "(%d) [ERROR] invalid log format of printing\n",
		    g_logger->pid);
		return 1;
	}
	t = time(NULL);
	localtime_r(&t, &tm);
	switch (g_logger->log_type) {
	case LOG_TYPE_VALUE_FILE:
		logger_rotate(&tm);
		fp = (g_logger->log_state == LOG_ST_OPENED) ? g_logger->log : stderr;
		break;
	case LOG_TYPE_VALUE_SYSLOG:
		fp = NULL;
		break;
	case LOG_TYPE_VALUE_STDOUT:
		fp = stdout;
		break;
	case LOG_TYPE_VALUE_STDERR:
	default:
		fp = stderr;
		break;
	}
	va_start(ap, fmt);
	logging_base(fp, level, g_logger->log_type, name, fmt, ap, &tm);
	va_end(ap);
	if (g_logger->log_type == LOG_TYPE_VALUE_FILE) {
		fflush(g_logger->log);
	}

	return 0;
}

int
logger_open(
    log_level_t level,
    const char *type,
    const char *ident,
    int option,
    const char *facility,
    const char *logfile)
{
	int error = 0;
	char *dup_logfile = NULL;

	ASSERT(g_logger != NULL);
	ASSERT(type != NULL);

	if (strcasecmp(type, "file") == 0 &&
	    (logfile == NULL || logfile[0] == '\0')) {
		errno = EINVAL;
		return 1;
	}
	if (logfile && logfile != '\0') {
		dup_logfile = strdup(logfile);
		if (dup_logfile == NULL) {
			return 1;
		}
	}
	if (g_logger->log_state == LOG_ST_OPENED) {
		if (g_logger->log_type == LOG_TYPE_VALUE_FILE) {
			if (g_logger->log == NULL) {
				fprintf(stderr,
				    "did not opened log file %s.",
				    g_logger->logfilename);
			} else {
				fclose(g_logger->log);
				g_logger->log = NULL;
			}
			free(g_logger->logfilename);
			g_logger->logfilename = NULL;
		} else if (g_logger->log_type == LOG_TYPE_VALUE_SYSLOG) {
			closelog();
		}
		g_logger->log_state = LOG_ST_CLOSED;
		g_logger->log_type = LOG_TYPE_VALUE_STDERR;
	}
	if (strcasecmp(type, LOG_TYPE_FILE) == 0) {
		if (logger_file_open(dup_logfile)) {
			g_logger->log_type = LOG_TYPE_VALUE_STDERR;
		} else {
			g_logger->log_type = LOG_TYPE_VALUE_FILE;
			g_logger->logfilename = dup_logfile;
		}
	} else if (strcasecmp(type, LOG_TYPE_SYSLOG) == 0) {
		logger_syslog_open(ident, option, facility);
		g_logger->log_type = LOG_TYPE_VALUE_SYSLOG;
	} else if (strcasecmp(type, LOG_TYPE_STDOUT) == 0) {
		g_logger->log_type = LOG_TYPE_VALUE_STDOUT;
	} else {
		g_logger->log_type = LOG_TYPE_VALUE_STDERR;
	}
	g_logger->log_state = LOG_ST_OPENED;
	if (g_logger->log_type != LOG_TYPE_VALUE_FILE) {
		free(dup_logfile);
	}
	if (level > LOG_LV_MIN && level < LOG_LV_MAX) {
		g_logger->verbose_level = level;
	} else {
		g_logger->verbose_level = DEFAULT_VERBOSE_LEVEL;
	}
	g_logger->pid = getpid();
	if (error) {
		free(dup_logfile);
	} else {
		if (g_logger->verbose_level >= LOG_LV_DEBUG) {
			LOG(LOG_LV_DEBUG,
			    "logging info: type = %d, level %d, state %d, pid %d",
			    g_logger->log_type,
			    g_logger->verbose_level,
			    g_logger->log_state,
			    g_logger->pid);
		}
	}

	return error;
}

void
logger_close(void)
{
	ASSERT(g_logger != NULL);

	if (g_logger->log_state == LOG_ST_OPENED) {
		switch (g_logger->log_type) {
		case LOG_TYPE_VALUE_FILE:
			if (g_logger->log == NULL) {
				fprintf(stderr,
				    "did not opened log file %s.",
				    g_logger->logfilename);
			} else {
				fclose(g_logger->log);
				g_logger->log = NULL;
			}
			free(g_logger->logfilename);
			g_logger->logfilename = NULL;
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		case LOG_TYPE_VALUE_SYSLOG:
			closelog();
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		default:
			g_logger->log_state = LOG_ST_CLOSED;
			break;
		}
	}
	g_logger->log_type = LOG_TYPE_VALUE_STDERR;
}

int
logger_create()
{
	logger_t *new;

	if (g_logger != NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(logger_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0, sizeof(logger_t));
	new->log_type = LOG_TYPE_VALUE_STDERR;
	new->log_state = LOG_ST_INIT;
	new->verbose_level = LOG_LV_MAX - 1;
	g_logger = new;

	return 0;

fail:
	free(new);
	return 1;
}

int
logger_set_foreground(int foreground)
{
	if (g_logger == NULL) {
		errno = EINVAL;
		return 1;
	}
	g_logger->foreground = foreground;

	return 0;
}

int
logger_destroy(void)
{
	if (g_logger == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (g_logger->log_state == LOG_ST_OPENED) {
		logger_close();
	}
	free(g_logger);
	g_logger = NULL;

	return 0;
}

int
logger_change_log_level(
    log_level_t level)
{
	if (g_logger == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (level > LOG_LV_MIN && level < LOG_LV_MAX) {
		g_logger->verbose_level = level;
	} else {
		g_logger->verbose_level = DEFAULT_VERBOSE_LEVEL;
	}

	return 0;
}
