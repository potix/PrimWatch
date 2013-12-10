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

int watcher_groups_status_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name, int current_status, int valid),
    void *foreach_cb_arg);

int watcher_healths_status_foreach(
    watcher_t *watcher,
    void (*foreach_cb)(void *foreach_cb_arg, const char *name, int current_status, int valid),
    void *foreach_cb_arg);

int watcher_get_group(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *valid);

int watcher_get_health(
    watcher_t *watcher,
    const char *name,
    int *current_status,
    int *valid);

int watcher_update_group_status(
    watcher_t *watcher,
    const char *name,
    int current_status);

int watcher_update_health_status(
    watcher_t *watcher,
    const char *name,
    int current_status);

int watcher_update_group_valid(
    watcher_t *watcher,
    const char *name,
    int valid);

int watcher_update_health_valid(
    watcher_t *watcher,
    const char *name,
    int valid);

#endif
