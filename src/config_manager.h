#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "bson.h"

typedef struct config_manager config_manager_t;

int config_manager_create(
    config_manager_t **config_manager);

int config_manager_destroy(
    config_manager_t *config_manager);

int config_manager_load(
    config_manager_t *config_manager,
    const char *config_file_path);

int config_manager_dump(
    config_manager_t *config_manager);

int config_manager_get_config(
    config_manager_t *config_manager,
    bson **config);

int config_manager_get_string(
    config_manager_t *config_manager,
    char const **s,
    const char *path,
    const char *default_path);

int config_manager_get_bool(
    config_manager_t *config_manager,
    int *b,
    const char *path,
    const char *default_path);

int config_manager_get_long(
    config_manager_t *config_manager,
    int64_t *l,
    const char *path,
    const char *default_path);

#endif
