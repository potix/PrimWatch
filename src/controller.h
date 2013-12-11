#ifndef CONTROLLER_H
#define CONTROLLER_H

#define MAX_LINE_BUFFER 2048

int controller_create(
    controller_t **controller,
    struct event_base *event_base,
    watcher_t *watcher);

int controller_destroy(
    controller_t *controller);

int controller_start(
    controller_t *controller);

int controller_stop(
    controller_t *controller);

#endif
