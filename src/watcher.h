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

#endif
