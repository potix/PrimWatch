#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "common_define.h"
#include "common_macro.h"
#include "config_manager.h"
#include "string_util.h"
#include "logger.h"
#include "watcher.h"
#include "tcp_server.h"
#include "controller.h"

#define DEFAULT_BUFFER_SIZE (NI_MAXHOST + INET6_ADDRSTRLEN + MAX_LINE_BUFFER + 1024)

struct controller {
	struct event_base *event_base;
	watcher_t *watcher;
	tcp_server_t *tcp_server;
	char *result;
	size_t result_size;
	size_t result_real_size;
};

static int controller_glow_result_buffer(
    controller_t *controller,
    size_t lacked_size);
static void controller_groups_status_foreach_cb(
    void *foreach_cb_arg,
    const char *name);
static void controller_healths_status_foreach_cb(
    void *foreach_cb_arg,
    const char *name);
static void controller_execute_command(
    controller_t *controller,
    parse_cmd_t *parse_cmd);
static int controller_on_recv_line(
    char **result,
    size_t *result_size,
    char *line,
    void *on_recv_line_cb_arg);

static int
controller_glow_result_buffer(
    controller_t *controller,
     size_t lacked_size)
{
	void *new_mem;
	size_t new_size;

	ASSERT(controller != NULL);
	ASSERT(lacked_size > 0);

	new_size = (controller->result_size + lacked_size) * 2;
	new_mem = realloc(controller->result, new_size);
	if (new_mem == NULL) {
		LOG(LOG_LV_ERR, "failed in reallocate memory of result buffer");
		return 1;
	}
	controller->result = new_mem;
	controller->result_size = new_size;
	
	return 0;
}

static void
controller_groups_status_foreach_cb(
    void *foreach_cb_arg,
    const char *name)
{
	controller_t *controller = foreach_cb_arg;
	size_t need_size;
	int wlen;

	ASSERT(controller != NULL);

	if (controller->result_real_size == 0) {
		wlen = snprintf(controller->result, controller->result_size, "OK health:\n");
		controller->result_real_size += wlen;
	}
	need_size = controller->result_real_size + strlen(name) + 6 /* space * 4 + newline + termination */;
	if (need_size > controller->result_size) {
		if (controller_glow_result_buffer(controller, need_size - controller->result_size)) {
			LOG(LOG_LV_ERR, "failed in glow buffer of result");
		}
	}
	wlen = snprintf(&controller->result[controller->result_real_size],
	    controller->result_size - controller->result_real_size, "    %s\n", name);
	controller->result_real_size += wlen;

} 

static void
controller_healths_status_foreach_cb(
    void *foreach_cb_arg,
    const char *name)
{
	controller_t *controller = foreach_cb_arg;
	size_t need_size;
	int wlen;

	ASSERT(controller != NULL);

	if (controller->result_real_size == 0) {
		wlen = snprintf(controller->result, controller->result_size, "OK health:\n");
		controller->result_real_size += wlen;
	}
	need_size = controller->result_real_size + strlen(name) + 6 /* space * 4 + newline + termination */;
	if (need_size > controller->result_size) {
		if (controller_glow_result_buffer(controller, need_size - controller->result_size)) {
			LOG(LOG_LV_ERR, "failed in glow buffer of result");
		}
	}
	wlen = snprintf(&controller->result[controller->result_real_size],
	    controller->result_size - controller->result_real_size, "    %s\n", name);
	controller->result_real_size += wlen;
}

/*
 *command:
 *    show groups
 *    show healths
 *    show group <group>
 *    show health <address>
 *    set status group <group> <up|down>
 *    set status health <address> <up|down>
 *    set valid group <group> <true|false>
 *    set valid health <address> <true|false>
 */
static void
controller_execute_command(
    controller_t *controller,
    parse_cmd_t *parse_cmd)
{
	const char *err_msg = NULL;
	int wlen;
	int current_status = 0;
	int valid = 0;
	int i;
	size_t need_size;

	ASSERT(controller != NULL);
	ASSERT(parse_cmd != NULL);

	if (parse_cmd->arg_size > 5) {
		err_msg = "too many arguments";
		goto fail;
	}
	if (strcasecmp(parse_cmd->args[0], "show") == 0) {
		if (parse_cmd->arg_size < 2) {
			err_msg = "too few arguments";
			goto fail;
		}
		if (strcasecmp(parse_cmd->args[1], "groups") == 0) {
			if (watcher_groups_status_foreach(controller->watcher, controller_groups_status_foreach_cb, controller)) {
				err_msg = "failed in gather status of groups";
				goto fail;
			}
			controller->result_real_size += 1;
		} else if (strcasecmp(parse_cmd->args[1], "healths") == 0) {
			if (watcher_healths_status_foreach(controller->watcher, controller_healths_status_foreach_cb, controller)) {
				err_msg = "failed in gather status of healths";
				goto fail;
			}
			controller->result_real_size += 1;
		} else if (strcasecmp(parse_cmd->args[1], "group") == 0) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (watcher_get_group(controller->watcher, parse_cmd->args[2], &current_status, &valid)) {
				err_msg = "failed in get status of group";
				goto fail;
			}
			wlen = snprintf(controller->result, controller->result_size, "OK group=%s, status=%s, valid=%s\n",
			    parse_cmd->args[2], (current_status) ? "up":"down", (valid) ? "true":"false");
			controller->result_real_size += wlen + 1;
		} else if (strcasecmp(parse_cmd->args[1], "health") == 0) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (watcher_get_health(controller->watcher, parse_cmd->args[2], &current_status, &valid)) {
				err_msg = "failed in get status of health";
				goto fail;
			}
			wlen = snprintf(controller->result, controller->result_size, "OK address=%s, status=%s, valid=%s\n",
			    parse_cmd->args[2], (current_status) ? "up":"down", (valid) ? "true":"false");
			controller->result_real_size += wlen + 1;
		} else {
			err_msg = "unexpected command";
			goto fail;
		}
	} else if (strcasecmp(parse_cmd->args[0], "set") == 0) {
		if (parse_cmd->arg_size < 2) {
			err_msg = "too few arguments";
			goto fail;
		}
		if (strcasecmp(parse_cmd->args[1], "status") == 0) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (strcasecmp(parse_cmd->args[2], "group") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "up") == 0) {
					current_status = 1;
				} else if (strcasecmp(parse_cmd->args[4], "down") == 0) {
					current_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				} 
				if (watcher_update_group_status(controller->watcher, parse_cmd->args[3], current_status)) {
					err_msg = "can not update staus of group";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK group=%s status=%s\n", parse_cmd->args[3], (current_status) ? "up":"down");
				controller->result_real_size += wlen + 1;
			} else if (strcasecmp(parse_cmd->args[2], "health") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "up") == 0) {
					current_status = 1;
				} else if (strcasecmp(parse_cmd->args[4], "down") == 0) {
					current_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_health_status(controller->watcher, parse_cmd->args[3], current_status)) {
					err_msg = "can not update staus of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK address=%s status=%s\n", parse_cmd->args[3], (current_status) ? "up":"down");
				controller->result_real_size += wlen + 1;
			} else {
				err_msg = "unexpected command";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->args[1], "valid") == 0) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (strcasecmp(parse_cmd->args[2], "group") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "true") == 0) {
					valid = 1;
				} else if (strcasecmp(parse_cmd->args[4], "false") == 0) {
					valid = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_group_valid(controller->watcher, parse_cmd->args[3], valid)) {
					err_msg = "can not update valid of group";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK group=%s valid=%s\n", parse_cmd->args[3], (valid) ? "true":"false");
				controller->result_real_size += wlen + 1;
			} else if (strcasecmp(parse_cmd->args[2], "health") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "true") == 0) {
					valid = 1;
				} else if (strcasecmp(parse_cmd->args[4], "false") == 0) {
					valid = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_health_valid(controller->watcher, parse_cmd->args[3], valid)) {
					err_msg = "can not update valid of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK address=%s valid=%s\n", parse_cmd->args[3], (valid) ? "true":"false");
				controller->result_real_size += wlen + 1;
			} else {
				err_msg = "unexpected command";
				goto fail;
			}
		} else {
			err_msg = "unexpected command";
			goto fail;
		}
	} else {
		err_msg = "unexpected command";
		goto fail;
	}

	return;

fail:
	wlen = snprintf(controller->result, controller->result_size, "NG %s >", err_msg);
	controller->result_real_size += wlen;
	for (i = 0; i < parse_cmd->arg_size; i++) {
		need_size = controller->result_real_size + strlen(parse_cmd->args[i]) + 3 /* space + newline + termination */;
		if (need_size > controller->result_size) {
			if (controller_glow_result_buffer(controller, need_size - controller->result_size)) {
				LOG(LOG_LV_ERR, "failed in glow buffer of result");
			}
		}
		wlen = snprintf(&controller->result[controller->result_real_size],
		    controller->result_size - controller->result_real_size, " %s", parse_cmd->args[i]);
		controller->result_real_size += wlen;
	}
	controller->result[controller->result_real_size] = '\0';
	LOG(LOG_LV_ERR, "%s", controller->result);
	controller->result[controller->result_real_size] = '\n';
	controller->result[controller->result_real_size + 1] = '\0';
	controller->result_real_size += 2;

	return;
}

static int
controller_on_recv_line(
    char **result,
    size_t *result_size,
    char *line,
    void *on_recv_line_cb_arg)
{
	controller_t *controller = on_recv_line_cb_arg;
	parse_cmd_t parse_cmd;

	ASSERT(result != NULL);
	ASSERT(result_size != NULL);
	ASSERT(line != NULL);
	ASSERT(controller != NULL);

	if (parse_cmd_b(&parse_cmd, line)) {
		LOG(LOG_LV_ERR, "failed in parse_command");
		return 1;
	}
	controller_execute_command(controller, &parse_cmd);
	*result = controller->result;
	*result_size = controller->result_real_size;
	controller->result_real_size = 0;

	return 0;
}

int
controller_create(
    controller_t **controller,
    struct event_base *event_base,
    watcher_t *watcher)
{
	controller_t *new = NULL;
	char  *new_result = NULL;

	if (controller == NULL ||
	    event_base == NULL ||
	    watcher == NULL) {
		errno = EINVAL;
		return 1;
	}

	new = malloc(sizeof(controller_t));
	if (new == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate controller");
		goto fail;
	}
	new_result = malloc(DEFAULT_BUFFER_SIZE);
	if (new_result == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate result buffer");
		goto fail;
	}
	new->watcher = watcher;
	new->tcp_server = NULL;
	new->result = new_result;
	new->result_size = DEFAULT_BUFFER_SIZE;
	new->result_real_size = 0;
	new->event_base = event_base;
	*controller = new;

	return 0;

fail:
	if (new_result) {
		free(new_result);
	}
	if (new) {
		free(new);
	}

	return 1;
}

int 
controller_destroy(
    controller_t *controller)
{
	if (controller == NULL) {
		errno = EINVAL;
		return 1;
	}

	if (controller->result) {
		free(controller->result);
	}
	if (controller) {
		free(controller);
	}

	return 0;
}

int 
controller_start(
    controller_t *controller)
{
	if (controller == NULL) {
		errno = EINVAL;
		return 1;
	}

	if (tcp_server_start(&controller->tcp_server, controller->event_base,
	     SERVER_HOST, SERVER_PORT, controller_on_recv_line, controller)) {
		return 1;
	}

	return 0;
}

int 
controller_stop(
    controller_t *controller)
{
	if (controller == NULL ||
	    controller->tcp_server == NULL) {
		errno = EINVAL;
		return 1;
	}

	if (tcp_server_stop(controller->tcp_server)) {
		return 1;
	}

	return 0;
}
