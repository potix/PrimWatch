#ifndef CONTROLLER_H
#define CONTROLLER_H

typedef struct controller controller_t;

int controller_create(
    controller_t **controller,
    struct event_base *event_base,
    watcher_t *watcher);

int controller_destroy(
    controller_t *controller);

int controller_start(
    controller_t *controller,
    const char *host,
    const char *serv);

int controller_stop(
    controller_t *controller);

#endif
