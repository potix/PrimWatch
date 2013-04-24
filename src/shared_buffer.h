#ifndef SHARED_BUFFER_H
#define SHARED_BUFFER_H

typedef enum shared_buffer_oflag shared_buffer_oflag_t;
typedef struct shared_buffer shared_buffer_t;

enum shared_buffer_oflag {
        SHBUF_OFL_READ = 0x01,
        SHBUF_OFL_WRITE = 0x02,
};

int shared_buffer_create(
    shared_buffer_t **shared_buffer);
    
int shared_buffer_destroy(
    shared_buffer_t *shared_buffer);
    
int shared_buffer_open(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    shared_buffer_oflag_t oflag);

int shared_buffer_close(
    shared_buffer_t *shared_buffer);

int shared_buffer_lock(
    shared_buffer_t *shared_buffer,
    shared_buffer_oflag_t oflag);

int shared_buffer_unlock(
    shared_buffer_t *shared_buffer);

int shared_buffer_rmap(
    shared_buffer_t *shared_buffer);

int shared_buffer_runmap(
    shared_buffer_t *shared_buffer); 

int shared_buffer_wmap(
    shared_buffer_t *shared_buffer,
    size_t map_size);

int shared_buffer_wunmap(
    shared_buffer_t *shared_buffer);

int shared_buffer_lock_map(
    shared_buffer_t *shared_buffer,
    size_t map_size);

int shared_buffer_unlock_unmap(
    shared_buffer_t *shared_buffer);

int shared_buffer_read(
    shared_buffer_t *shared_buffer,
    char **data,
    size_t *data_size);

int shared_buffer_write(
    shared_buffer_t *shared_buffer,
    const char *data,
    size_t data_size);

int shared_buffer_set_dirty(
    shared_buffer_t *shared_buffer);
    
#endif
