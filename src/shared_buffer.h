#ifndef SHARED_BUFFER_H
#define SHARED_BUFFER_H

typedef struct shared_buffer shared_buffer_t;

int shared_buffer_create(
    shared_buffer_t **shared_buffer);
    
int shared_buffer_destroy(
    shared_buffer_t *shared_buffer);
    
int shared_buffer_wopen(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    size_t memsize);

int shared_buffer_ropen(
    shared_buffer_t *shared_buffer,
    const char *file_path);
    
int shared_buffer_close(
    shared_buffer_t *shared_buffer);

int shared_buffer_read(
    shared_buffer_t *shared_buffer,
    char **data,
    size_t *data_size);

int shared_buffer_write(
    shared_buffer_t *shared_buffer,
    const char *data,
    size_t data_size);
    
#endif
