#ifndef EXECUTOR_H
#define EXECUTOR_H

#include <event.h>

typedef struct executor executor_t;
typedef enum exec_flag exec_flag_t;

enum exec_flag {
        EXEC_FL_NONE = 0,
        EXEC_FL_FINISH = 0x02,
};

int executor_create(
    executor_t **executor,
    struct event_base *event_base);

int executor_destroy(
    executor_t *executor);

int executor_exec(
    executor_t *executor,
    const char *cmd,
    void (*read_cb)(int fd, short ev, void *arg, exec_flag_t *flag),
    void *read_cb_arg);

int executor_waitpid(
    executor_t *executor);

#endif
