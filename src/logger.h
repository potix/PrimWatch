#ifndef LOGGER_H
#define LOGGER_H

#include <syslog.h>

#define LOG_TYPE_FILE	"file"
#define LOG_TYPE_SYSLOG	"syslog"
#define LOG_TYPE_STDERR	"stderr"
#define LOG_TYPE_STDOUT	"stdout"

#define LOG_FAC_DAEMON	"daemon"
#define LOG_FAC_USER	"user"
#define LOG_FAC_LOCAL0	"local0"
#define LOG_FAC_LOCAL1	"local1"
#define LOG_FAC_LOCAL2	"local2"
#define LOG_FAC_LOCAL3	"local3"
#define LOG_FAC_LOCAL4	"local4"
#define LOG_FAC_LOCAL5	"local5"
#define LOG_FAC_LOCAL6	"local6"
#define LOG_FAC_LOCAL7	"local7"

#define LOG(level, ...) logging(level, __func__, __VA_ARGS__)

enum log_level {
	LOG_LV_MIN	= 0,  	/* max */
	LOG_LV_EMERG	= 1,	/* system is unusable */
	LOG_LV_ALERT   	= 2,   	/* action must be taken immediately */
	LOG_LV_CRIT    	= 3,   	/* critical error conditions */
	LOG_LV_ERR     	= 4,   	/* error conditions */
	LOG_LV_WARNING 	= 5,   	/* warning conditions */
	LOG_LV_NOTICE  	= 6,   	/* normal but significant condition */
	LOG_LV_INFO    	= 7,   	/* informational */
	LOG_LV_DEBUG   	= 8,   	/* debug messages */
	LOG_LV_TRACE   	= 9,   	/* trace messages */
	LOG_LV_MAX	= 10,  	/* max */
};
typedef enum log_level log_level_t;

int logging(
    log_level_t level,
    const char *name,
    const char *fmt,
    ...);

int logger_open(
    log_level_t level,
    const char *type,
    const char *ident,
    int option,
    const char *facility,
    const char *logfile);

void logger_close(void);

int logger_create(int foreground);

int logger_destroy(void);

int logger_change_log_level(
    log_level_t level);

#endif
