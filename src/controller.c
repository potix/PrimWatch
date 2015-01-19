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
static void controller_common_foreach_cb(
    void *foreach_cb_arg,
    const char *name,
    const char *target);
static void controller_groups_foreach_cb(
    void *foreach_cb_arg,
    const char *name);
static void controller_addresses_foreach_cb(
    void *foreach_cb_arg,
    const char *name);
static void controller_hostnames_foreach_cb(
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
controller_common_foreach_cb(
    void *foreach_cb_arg,
    const char *name,
    const char *target)
{
	controller_t *controller = foreach_cb_arg;
	size_t need_size;
	int wlen;

	ASSERT(controller != NULL);

	if (controller->result_real_size == 0) {
		wlen = snprintf(controller->result, controller->result_size, "OK %s:\n", target);
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
controller_groups_foreach_cb(
    void *foreach_cb_arg,
    const char *name)
{
	controller_common_foreach_cb(foreach_cb_arg, name, "groups");
} 

static void
controller_addresses_foreach_cb(
    void *foreach_cb_arg,
    const char *name)
{
	controller_common_foreach_cb(foreach_cb_arg, name, "addresses");
}

static void
controller_hostnames_foreach_cb(
    void *foreach_cb_arg,
    const char *name)
{
	controller_common_foreach_cb(foreach_cb_arg, name, "hostnames");
}

/*
 *command:
 *    show groups
 *    show addresses 
 *    show hostnames
 *    show addressesHostnames
 *    show health group <group>
 *    show health address <address>
 *    show health hostname <hostname>
 *    show health addressHostname <address hostname>
 *    set status group <group> <up|down>
 *    set status address <address> <up|down>
 *    set status hostname <hostname> <up|down>
 *    set status addressHostname <address hostname> <up|down>
 *    set preempt_status group <group> <true|false>
 *    set preempt_status address <address> <true|false>
 *    set preempt_status hostname <hostname> <true|false>
 *    set preempt_status addressHostname <address hostname> <true|false>
 */
static void
controller_execute_command(
    controller_t *controller,
    parse_cmd_t *parse_cmd)
{
	const char *err_msg = NULL;
	int wlen;
	int current_status = 0;
	int previous_status = 0;
	int preempt_status = 0;
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
			if (watcher_groups_foreach(controller->watcher, controller_groups_foreach_cb, controller)) {
				err_msg = "failed in gather groups";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->args[1], "addresses") == 0) {
			if  (watcher_addresses_foreach(controller->watcher, controller_addresses_foreach_cb, controller)) {
				err_msg = "failed in gather addresses";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->args[1], "hostnames") == 0) {
			if  (watcher_hostnames_foreach(controller->watcher, controller_hostnames_foreach_cb, controller)) {
				err_msg = "failed in gather hostnames";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->args[1], "addressesHostnames") == 0) {
			if  (watcher_addresses_hostnames_foreach(controller->watcher, controller_hostnames_foreach_cb, controller)) {
				err_msg = "failed in gather addresses and hostnames";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->args[1], "health") == 0) {
			if (parse_cmd->arg_size < 2) {
				err_msg = "too few arguments";
				goto fail;
			}
			if (strcasecmp(parse_cmd->args[2], "group") == 0) {
				if (parse_cmd->arg_size < 4) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (watcher_get_group_health(controller->watcher, parse_cmd->args[3], &current_status, &previous_status, &preempt_status)) {
					err_msg = "failed in get status of group";
				goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				   "OK group=%s, current status=%s, previous status=%s, preempt status=%s\n",
				   parse_cmd->args[3], (current_status) ? "up" : "down", (previous_status) ? "up" : "down", (preempt_status) ? "true" : "false");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "address") == 0) {
				if (parse_cmd->arg_size < 4) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (watcher_get_address_health(controller->watcher, parse_cmd->args[3], &current_status, &previous_status, &preempt_status)) {
					err_msg = "failed in get status of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				   "OK address=%s, current status=%s, previous status=%s, preempt status=%s\n",
				   parse_cmd->args[3], (current_status) ? "up" : "down", (previous_status) ? "up" : "down", (preempt_status) ? "true" : "false");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "hostname") == 0) {
				if (parse_cmd->arg_size < 4) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (watcher_get_hostname_health(controller->watcher, parse_cmd->args[3], &current_status, &previous_status, &preempt_status)) {
					err_msg = "failed in get status of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				   "OK hostname=%s, current status=%s, previous status=%s, preempt status=%s\n",
				   parse_cmd->args[3], (current_status) ? "up" : "down", (previous_status) ? "up" : "down", (preempt_status) ? "true" : "false");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "addressHostname") == 0) {
				if (parse_cmd->arg_size < 4) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (watcher_get_address_hostname_health(controller->watcher, parse_cmd->args[3], &current_status, &previous_status, &preempt_status)) {
					err_msg = "failed in get status of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				   "OK address and hostname=%s, current status=%s, previous status=%s, preempt status=%s\n",
				   parse_cmd->args[3], (current_status) ? "up" : "down", (previous_status) ? "up" : "down", (preempt_status) ? "true" : "false");
				controller->result_real_size += wlen;
			}

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
				if (watcher_update_group_health_status(controller->watcher, parse_cmd->args[3], current_status)) {
					err_msg = "can not update staus of group";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK group=%s current status=%s\n", parse_cmd->args[3], (current_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "address") == 0) {
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
				if (watcher_update_address_health_status(controller->watcher, parse_cmd->args[3], current_status)) {
					err_msg = "can not update staus of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK address=%s current status=%s\n", parse_cmd->args[3], (current_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "hostname") == 0) {
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
				if (watcher_update_hostname_health_status(controller->watcher, parse_cmd->args[3], current_status)) {
					err_msg = "can not update staus of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK hostname=%s current status=%s\n", parse_cmd->args[3], (current_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "addressHostname") == 0) {
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
				if (watcher_update_address_hostname_health_status(controller->watcher, parse_cmd->args[3], current_status)) {
					err_msg = "can not update staus of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK address and hostname=%s current status=%s\n", parse_cmd->args[3], (current_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else {
				err_msg = "unexpected command";
				goto fail;
			}
		} else if (strcasecmp(parse_cmd->args[1], "preempt_status") == 0) {
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
					preempt_status = 1;
				} else if (strcasecmp(parse_cmd->args[4], "down") == 0) {
					preempt_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_group_health_preempt_status(controller->watcher, parse_cmd->args[3], preempt_status)) {
					err_msg = "can not update preempt status of group";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK group=%s preempt status=%s\n", parse_cmd->args[3], (preempt_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "address") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "up") == 0) {
					preempt_status = 1;
				} else if (strcasecmp(parse_cmd->args[4], "down") == 0) {
					preempt_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_address_health_preempt_status(controller->watcher, parse_cmd->args[3], preempt_status)) {
					err_msg = "can not update preempt status of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK address=%s preempt_status=%s\n", parse_cmd->args[3], (preempt_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "hostname") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "up") == 0) {
					preempt_status = 1;
				} else if (strcasecmp(parse_cmd->args[4], "down") == 0) {
					preempt_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_hostname_health_preempt_status(controller->watcher, parse_cmd->args[3], preempt_status)) {
					err_msg = "can not update preempt status of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK hostname=%s preempt_status=%s\n", parse_cmd->args[3], (preempt_status) ? "up":"down");
				controller->result_real_size += wlen;
			} else if (strcasecmp(parse_cmd->args[2], "addressHostname") == 0) {
				if (parse_cmd->arg_size < 5) {
					err_msg = "too few arguments";
					goto fail;
				}
				if (strcasecmp(parse_cmd->args[4], "up") == 0) {
					preempt_status = 1;
				} else if (strcasecmp(parse_cmd->args[4], "down") == 0) {
					preempt_status = 0;
				} else {
					err_msg = "invalid parameter";
					goto fail;
				}
				if (watcher_update_address_hostname_health_preempt_status(controller->watcher, parse_cmd->args[3], preempt_status)) {
					err_msg = "can not update preempt status of health";
					goto fail;
				}
				wlen = snprintf(controller->result, controller->result_size,
				    "OK address and hostname=%s preempt_status=%s\n", parse_cmd->args[3], (preempt_status) ? "up":"down");
				controller->result_real_size += wlen;
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
	LOG(LOG_LV_WARNING, "%s", controller->result);
	controller->result[controller->result_real_size] = '\n';
	controller->result[controller->result_real_size + 1] = '\0';
	controller->result_real_size += 1;

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
		LOG(LOG_LV_WARNING, "failed in parse_command");
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
	memset(new, 0, sizeof(controller_t));
	new_result = malloc(DEFAULT_BUFFER_SIZE);
	if (new_result == NULL) {
		LOG(LOG_LV_ERR, "failed in allocate result buffer");
		goto fail;
	}
	new->watcher = watcher;
	new->result = new_result;
	new->result_size = DEFAULT_BUFFER_SIZE;
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
    controller_t *controller,
    const char *host,
    const char *serv)
{
	if (controller == NULL) {
		errno = EINVAL;
		return 1;
	}

	if (tcp_server_start(&controller->tcp_server, controller->event_base,
	    host, serv, controller_on_recv_line, controller)) {
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
