#include <sys/types.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <errno.h>
#include <event.h>
#include <limits.h>

#include "common_macro.h"
#include "logger.h"
#include "executor.h"
#include "string_util.h"

typedef struct executor_process executor_process_t;

struct executor_process {
	int fd[2];
	pid_t pid;
	struct event read_event;
	char *cmd;
	void (*read_cb)(int fd, short ev, void *arg, exec_flag_t *flag);
	void *read_cb_arg;
	LIST_ENTRY(executor_process) next;
};

struct executor {
	LIST_HEAD(executor_process_head, executor_process) process_head;
	int process_cnt;	
	struct event_base *event_base;
};

static int executor_process_create(
    executor_process_t **process,
    const char *cmd,
    void (*read_cb)(int fd, short ev, void *arg, exec_flag_t *flag),
    void *read_cb_arg);
static void executor_process_destroy(executor_process_t *process);
static void executor_read(int fd, short ev, void *arg);

static int
executor_process_create(
    executor_process_t **process,
    const char *cmd,
    void (*read_cb)(int fd, short ev, void *arg, exec_flag_t *flag),
    void *read_cb_arg)
{
	executor_process_t *new = NULL;
	char *new_cmd = NULL;

	ASSERT(process != NULL);
	ASSERT(cmd != NULL);
	ASSERT(read_cb != NULL);

	new = malloc(sizeof(executor_process_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0, sizeof(executor_process_t));
	new->fd[0] = -1;
	new->fd[1] = -1;
	new->read_cb = read_cb;
	new->read_cb_arg = read_cb_arg;
	new_cmd = strdup(cmd);
	if (new_cmd == NULL) {
		goto fail;
	}
	new->cmd = new_cmd;
	*process = new;

	return 0;

fail:
	if (new->fd[0] != -1) {
		close(new->fd[0]);
	}
	if (new->fd[1] != -1) {
		close(new->fd[1]);
	}
	free(new_cmd);
	free(new);

	return 1;
}

static void
executor_process_destroy(
    executor_process_t *process)
{
	ASSERT(process != NULL);

	if (process->fd[0] != -1) {
		close(process->fd[0]);
	}
	if (process->fd[1] != -1) {
		close(process->fd[1]);
	}
	free(process->cmd);
	free(process);
}

static void
executor_read(
    int fd,
    short ev,
    void *arg)
{
	executor_process_t *process = arg;
	exec_flag_t exec_flag = EXEC_FL_NONE;
	
	ASSERT(ev == EV_READ);
	process->read_cb(fd, ev, process->read_cb_arg, &exec_flag);
	if (exec_flag == EXEC_FL_FINISH) {
		event_del(&process->read_event);
	}
}

int
executor_create(
    executor_t **executor,
    struct event_base *event_base)
{
	executor_t *new = NULL;

	if (executor == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(executor_t));
	if (new == NULL) {
		goto fail;
	}
	LIST_INIT(&new->process_head);
	new->event_base = event_base;
	*executor = new;

	return 0;

fail:
	free(new);

	return 1;
}

int
executor_destroy(
    executor_t *executor)
{
	executor_process_t *process, *process_next;

	if (executor == NULL) {
		errno = EINVAL;
		return 1;
	}
	process = LIST_FIRST(&executor->process_head);
        while(process) {
		process_next = LIST_NEXT(process, next);
		LIST_REMOVE(process, next);
		executor_process_destroy(process);
		process = process_next;		
	}
	free(executor);

	return 0;
}

int
executor_exec(
    executor_t *executor,
    const char *cmd,
    void read_cb(int fd, short ev, void *arg, exec_flag_t *flag),
    void *read_cb_arg)
{
	executor_process_t *process = NULL;
	parse_cmd_t parse_cmd;

	if (executor_process_create(
	    &process,
	    cmd,
	    read_cb,
	    read_cb_arg)) {
		LOG(LOG_LV_ERR, "can not create process");
		goto fail;
	}
	if (parse_cmd_b(&parse_cmd, process->cmd)) {
		LOG(LOG_LV_ERR, "can not parse command");
		goto fail;
	}
	if (pipe(process->fd) < 0) {
		LOG(LOG_LV_ERR, "can not create pipe of process");
		goto fail;
	}
	if ((process->pid = fork()) < 0) {
		LOG(LOG_LV_ERR, "can not fork process");
        	goto fail;
	} else if (process->pid == 0) {
		/* child */

		close(process->fd[0]);
		if (dup2(process->fd[1], 1) < 0) {
			exit(1);
		}
		close(process->fd[1]);
		execvp(parse_cmd.args[0], parse_cmd.args);
		_exit(EX_OSERR);
	} else {
		/* parent */
		LIST_INSERT_HEAD(&executor->process_head, process, next);
		event_set(&process->read_event, process->fd[0], EV_READ|EV_PERSIST, executor_read, process);
		event_base_set(executor->event_base, &process->read_event);
		event_add(&process->read_event, NULL);
       		close(process->fd[1]);
		process->fd[1] = -1;
	}

	return 0;

fail:
	if (process) {
		executor_process_destroy(process);
	}

	return 1;
}

int
executor_waitpid(
    executor_t *executor)
{
	executor_process_t *process, *process_next;
	int status;

	if (executor == NULL) {
		errno = EINVAL;
		return 1;
	}
	process = LIST_FIRST(&executor->process_head);
	while (process) {
		process_next = LIST_NEXT(process, next);
		if (event_pending(&process->read_event, EV_READ, NULL)) {
		        process = process_next;
			continue;
		}
		if (waitpid(process->pid, &status, WNOHANG) == process->pid) {
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
				LOG(LOG_LV_ERR, "executed process error");
			}
			LIST_REMOVE(process, next);
			executor_process_destroy(process);
		}
		process = process_next;
	}

	return 0;
}
