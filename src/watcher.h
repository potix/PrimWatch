#ifndef WATCHER_H
#define WATCHER_H

#include <event.h>

typedef struct watcher watcher_t;

int watcher_create(
    watcher_t **watcher,
    struct event_base *event_base,
    config_manager_t *config_manager);

int watcher_destroy(
    watcher_t *watcher);

int watcher_polling_start(
    watcher_t *watcher);

int watcher_polling_stop(
    watcher_t *watcher);

int watcher_sigchild(
    watcher_t *watcher);

int watcher_groups_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg);

int watcher_addresses_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg);

int watcher_hostnames_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name),
    void *foreach_cb_arg);

int watcher_get_group_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status);

int watcher_get_address_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status);

int watcher_get_hostname_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *previous_status,
    int *preempt_status);

int watcher_update_group_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status);

int watcher_update_address_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status);

int watcher_update_hostname_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status);

int watcher_update_group_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status);

int watcher_update_address_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status);

int watcher_update_hostname_health_preempt_status(
    watcher_t *watcher,
    const char *name,
    int preempt_status);

#endif
