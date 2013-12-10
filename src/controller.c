#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "watcher.h"
#include "tcp_server.h"

#define DEFAULT_BUFER_SIZE 65553

struct controller {
	struct event_base *event_base;
	watcher_t *watcher;
	tcp_server_t *tcp_server;
	char *result;
	size_t result_size;
	size_t result_real_size;
};

static int controller_status_foreach(
    void *foreach_cb_arg,
    const char *name,
    int current_status,
    int valid);


static int
controller_glow_result(
   // XXXX)
{


}


static int
controller_status_foreach(
    void *foreach_cb_arg,
    const char *name)
{
	//xxxxx

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
void
controller_execute_command(parse_cmd_t *parse_cmd, controller_t *controller)
{
	const char *err_msg = NULL;
	size_t msg_size;
	int wlen;

	if (parse_cmd->arg_size > 5) {
		err_msg = "too many arguments";
		goto fail;
	}
	if (strcasecmp(parse_cmd->arg[0],"show")) {
		if (parse_cmd->arg_size < 2) {
			err_msg = "too few arguments";
			goto fail;
		}
		if (strcasecmp(parse_cmd->arg[1],"groups")) {
			if (watcher_groups_status_foreach(controller->watcher, controller_status_foreach, controller)) {
				err_msg = "failed in gather status of groups";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->arg[1],"healths")) {
			if (watcher_healths_status_foreach(controller->watcher, controller_status_foreach, controller)) {
				err_msg = "failed in gather status of healths";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->arg[1],"group")) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (watcher_get_group(controller->watcher, parse_cmd->arg[2], &current_status, &valid)) {
				err_msg = "failed in get status of group";
				goto fail;
			}
			/* XXXX */
		} else if (strcasecmp(parse_cmd->arg[1],"health")) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (watcher_get_health(controller->watcher, parse_cmd->arg[2], &current_status, &valid)) {
				err_msg = "failed in get status of health";
				goto fail;
			}
			/* XXXX */
		} else {
			err_msg = "unexpected command";
			goto fail;
		}
	} else if (strcasecmp(parse_cmd->arg[0],"set")) {
		if (parse_cmd->arg_size < 2) {
			err_msg = "too few arguments";
			goto fail;
		}
		if (strcasecmp(parse_cmd->arg[1],"status")) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (strcasecmp(parse_cmd->arg[2],"group")) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->arg[4], "up") == 0) {
					current_status = 1;
				} else if (strcasecmp(parse_cmd->arg[4], "down") == 0) {
					current_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				} 
				if (watcher_update_group_status(controller->watcher, parse_cmd->arg[3], current_status)) {
					err_msg = "can not update staus of group";
					goto fail;
				}
				// XXXXXX
			} else if (strcasecmp(parse_cmd->arg[2],"health")) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->arg[4], "up") == 0) {
					current_status = 1;
				} else if (strcasecmp(parse_cmd->arg[4], "down") == 0) {
					current_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_health_status(controller->watcher, parse_cmd->arg[3], current_status)) {
					err_msg = "can not update staus of health";
					goto fail;
				}
				// XXXXX
			} else {
				err_msg = "unexpected command";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->arg[1],"valid")) {
			if (parse_cmd->arg_size < 3) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (strcasecmp(parse_cmd->arg[2],"group")) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->arg[4], "true") == 0) {
					valid = 1;
				} else if (strcasecmp(parse_cmd->arg[4], "false") == 0) {
					valid = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_group_valid(controller->watcher, parse_cmd->arg[3], valid)) {
					err_msg = "can not update valid of group";
					goto fail;
				}
				// XXXX
			} else if (strcasecmp(parse_cmd->arg[2],"health")) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->arg[4], "true") == 0) {
					valid = 1;
				} else if (strcasecmp(parse_cmd->arg[4], "false") == 0) {
					valid = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_health_valid(controller->watcher, parse_cmd->arg[3], valid)) {
					err_msg = "can not update valid of health";
					goto fail;
				}
				// XXXX
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
	wlen = snprintf(controller->result, controller->result_size, "%s > ", err_msg);
	controller->result_real_size += wlen;
	for (i = 0; i < parse_cmd->arg_size; i++) {
		wlen = snprintf(&controller->result[controller->result_real_size],
		    controller->result_size - controller->result_real_size, "%s ", parse_cmd->arg[i]);
		controller->result_real_size += wlen;
	}
	controller->result_real_size += 1;
	LOG(LOG_LV_ERR, "command error: %s", controller->result);

	return;
}

int
controller_on_recv_line(char **result, size_t *result_size, char *line, void *on_recv_line_cb_arg)
{
	parse_cmd_t parse_cmd;
	controller_t *controller;

	ASSERT(controller != NULL);

	if (parse_cmd_b(&parse_cmd, line)) {
		LOG(LOG_LV_ERR, "failed in parse_command");
		return 1;
	}
	controller_execute_command(&parse_cmd, controller);
	*result = controller->result;
	*result_size = controller->result_real_size;

	return 0;
}

int
controller_create(controller_t **controller, struct event_base *event_base, watcher_t *watcher)
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
	if (mew == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate controller");
		goto fail;
	}
	new_result = malloc(DEFAULT_BUFFER_SIZE);
	if (new_result = NULL) {
		LOG(LOG_LV_ERR, "failed in allocate result buffer");
		goto fail;
	}
	new->watcher = watcher;
	new->tcp_server = NULL;
	new->result = new_result;
	new->result_size = DEFAULT_BUFFER_SIZE;
	new->result_real_size = 0;
	new->event_base = event_base;

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
controller_destroy(controller_t *controller)
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
controller_start(controller_t *controller)
{
	if (controller == NULL) {
		errno = EINVAL;
		return 1;
	}

	if (tcp_server_start(&controller->tcp_server,
	    controller->event_base, "127.0.0.1", "50000", controller_on_recv_line, controller)) {
		return 1;
	}

	return 0;
}

int 
controller_stop(controller_t *controller)
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
