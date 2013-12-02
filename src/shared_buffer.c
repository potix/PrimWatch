#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "common_macro.h"
#include "logger.h"
#include "shared_buffer.h"

#define DATA_SIZE_LENGTH sizeof(uint64_t)

struct shared_buffer {
	int fd;
	int dirty;
	uint8_t *read_addr;
	uint8_t *write_addr;
	size_t read_map_size;
	size_t write_map_size;
	int lock;
	shared_buffer_oflag_t lock_oflag;
	shared_buffer_oflag_t open_oflag;
};

static int shared_buffer_touch(
    shared_buffer_t *shared_buffer,
    const char *file_path);

static int
shared_buffer_touch(
    shared_buffer_t *shared_buffer,
    const char *file_path)
{
	int fd = -1;
	int lock_fl = 0;
	struct flock lock;
	uint64_t size;

	ASSERT(shared_buffer != NULL);
	ASSERT(file_path != NULL);
	fd = open(file_path, O_RDWR|O_CREAT|O_TRUNC|O_EXCL, 0644);
	if (fd < 0) {
		if (errno == EEXIST) {
			return 0;
		}
		LOG(LOG_LV_ERR, "fail in create shared buffer file\n");
		goto fail;
	}
	memset(&lock, 0, sizeof(lock));
	lock.l_whence = SEEK_SET;
	lock.l_type = F_WRLCK;
	while (fcntl(fd, F_SETLKW, &lock) != 0) {
		if (errno == EINTR) {
			continue;
		}
		LOG(LOG_LV_ERR, "failed in file lock %m\n");
		goto fail;
	}
	lock_fl = 1;
	if (ftruncate(fd, DATA_SIZE_LENGTH)) {
		LOG(LOG_LV_ERR, "fail in truncate (%m)\n");
	}
	write(fd, &size, sizeof(size));
	memset(&lock, 0, sizeof(lock));
	lock.l_whence = SEEK_SET;
	lock.l_type = F_UNLCK;
	fcntl(shared_buffer->fd, F_SETLK, &lock);
	close(fd);

	return 0;

fail:
	if (lock_fl) {
		memset(&lock, 0, sizeof(lock));
		lock.l_whence = SEEK_SET;
		lock.l_type = F_UNLCK;
		fcntl(shared_buffer->fd, F_SETLK, &lock);
	}
	if (fd != -1) {
		close(fd);
	}

	return 1;

}

int
shared_buffer_create(
    shared_buffer_t **shared_buffer)
{
	shared_buffer_t *new = NULL;
	
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(shared_buffer_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0 , sizeof(shared_buffer_t));
	new->fd = -1;
	*shared_buffer = new;

	return 0;

fail:
	free(new);

	return 1;
}

int
shared_buffer_destroy(
    shared_buffer_t *shared_buffer)
{
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd != -1) {
		shared_buffer_close(shared_buffer);
	}
	free(shared_buffer);

	return 0;
}

int
shared_buffer_open(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    shared_buffer_oflag_t oflag)
{
	mode_t mode = 0;
        int amode = 0;

	if (shared_buffer == NULL ||
	    file_path == NULL ||
	    oflag <= 0 ||
	    oflag > (SHBUF_OFL_READ|SHBUF_OFL_WRITE)) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd > -1) {
		LOG(LOG_LV_ERR, "already opened shared buffer file\n");
		return 1;
	}
	if (oflag & SHBUF_OFL_WRITE) {
		mode = O_WRONLY;
		amode |= W_OK;
	}
	if (oflag & SHBUF_OFL_READ) {
		if (mode == O_WRONLY) {
			mode = O_RDWR;
		} else {
			mode = O_RDONLY;
		}
		amode |= R_OK;
	}
	if (oflag & SHBUF_OFL_WRITE) {
		if (access(file_path, amode)) {
			if (shared_buffer_touch(shared_buffer, file_path)) {
				return 1;
			}
		}
	}
	shared_buffer->fd = open(file_path, mode);
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "failed in open shared file ((%m)\n");
		return 1;
	}
	shared_buffer->open_oflag = oflag;

	return 0;
}

int
shared_buffer_close(
    shared_buffer_t *shared_buffer)
{
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opened\n");
		return 1; 
	}
	if (shared_buffer->lock) {
		shared_buffer_unlock(shared_buffer);
	}
	if (shared_buffer->write_addr) {
		shared_buffer_wunmap(shared_buffer);
	}
	if (shared_buffer->read_addr) {
		shared_buffer_runmap(shared_buffer);
	}
	close(shared_buffer->fd);
	shared_buffer->fd = -1;
	shared_buffer->open_oflag = 0;

	return 0;
}

int
shared_buffer_lock(
    shared_buffer_t *shared_buffer,
    shared_buffer_oflag_t oflag)
{
	short type = 0;
	struct flock lock;

	if (shared_buffer == NULL ||
	    (oflag != SHBUF_OFL_WRITE && oflag != SHBUF_OFL_READ) ||
            !(shared_buffer->open_oflag & oflag)) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is already locked\n");
		return 1;
	}
	if (oflag & SHBUF_OFL_WRITE) {
		type = F_WRLCK;
	} else if(oflag & SHBUF_OFL_READ) {
		type = F_RDLCK;
	} else {
		/* NOTREACHED */
		ABORT("unexpected lock type");
		return 1;
	}
	memset(&lock, 0, sizeof(lock));
	lock.l_whence = SEEK_SET;
	lock.l_type = type;
	while (fcntl(shared_buffer->fd, F_SETLKW, &lock) != 0) {
		if (errno == EINTR) {
			continue;
		}
		LOG(LOG_LV_ERR, "failed in file lock (%m)\n");
		return 1;
	}
	shared_buffer->lock = 1;
	shared_buffer->lock_oflag = oflag;

	return 0;
}

int
shared_buffer_unlock(
    shared_buffer_t *shared_buffer)
{
	struct flock lock;

	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	memset(&lock, 0, sizeof(lock));
	lock.l_whence = SEEK_SET;
	lock.l_type = F_UNLCK;
	fcntl(shared_buffer->fd, F_SETLK, &lock);
	shared_buffer->lock = 0;
	shared_buffer->lock_oflag = 0;

	return 0;
}

int
shared_buffer_rmap(
    shared_buffer_t *shared_buffer)
{
	size_t data_size;
	uint8_t *addr_ptr;
	int proto;

	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (!(shared_buffer->open_oflag & SHBUF_OFL_READ)) {
		LOG(LOG_LV_ERR, "shared buffer is not readable\n");
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	if (shared_buffer->read_addr) {
		LOG(LOG_LV_ERR, "shared buffer is already mapped in reading\n");
		return 1;
	}
	addr_ptr = mmap(NULL, DATA_SIZE_LENGTH, PROT_READ, MAP_SHARED, shared_buffer->fd, 0);
	if (addr_ptr == MAP_FAILED) {
		LOG(LOG_LV_ERR, "failed in mmap %m\n");
		return 1;	
	}
	data_size = (size_t)(*((uint64_t *)addr_ptr));
	munmap(addr_ptr, DATA_SIZE_LENGTH);
	proto = PROT_READ;
	if (shared_buffer->lock_oflag == SHBUF_OFL_WRITE) {
		proto |= PROT_WRITE;
	}
	addr_ptr = mmap(NULL, data_size + DATA_SIZE_LENGTH, proto, MAP_SHARED, shared_buffer->fd, 0);
	if (addr_ptr == MAP_FAILED) {
		LOG(LOG_LV_ERR, "failed in mmap %m\n");
		return 1;
	}
	shared_buffer->read_addr = addr_ptr;
	shared_buffer->read_map_size = data_size + DATA_SIZE_LENGTH;

	return 0;
}

int
shared_buffer_runmap(
    shared_buffer_t *shared_buffer)
{
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (shared_buffer->read_addr == NULL) {
		LOG(LOG_LV_ERR, "shared buffer is not mapped in reading\n");
		return 1;
	}
	if (shared_buffer->dirty) {
		msync(shared_buffer->write_addr, shared_buffer->write_map_size, MS_SYNC);
		shared_buffer->dirty = 0;
	}
	munmap(shared_buffer->read_addr, shared_buffer->read_map_size);
	shared_buffer->read_addr = NULL;

	return 0;
}

int
shared_buffer_wmap(
    shared_buffer_t *shared_buffer,
    size_t map_size)
{
	uint8_t *addr_ptr;

	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (!(shared_buffer->open_oflag & SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "shared buffer is not writable\n");
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	if (!(shared_buffer->lock_oflag & SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "shared buffer is not writable locked\n");
		return 1;
	}
	if (shared_buffer->write_addr) {
		LOG(LOG_LV_ERR, "shared buffer is already mapped in writing\n");
		return 1;
	}
	if (ftruncate(shared_buffer->fd, map_size + DATA_SIZE_LENGTH)) {
		LOG(LOG_LV_ERR, "fail in truncate %m\n");
		return 1;
	}
	addr_ptr = mmap(NULL, map_size + DATA_SIZE_LENGTH, PROT_WRITE, MAP_SHARED, shared_buffer->fd, 0); 
	if (addr_ptr == MAP_FAILED) {
		LOG(LOG_LV_ERR, "failed in mmap %m\n");
		return 1;
	}
	shared_buffer->write_addr = addr_ptr;
	shared_buffer->write_map_size = map_size + DATA_SIZE_LENGTH;

	return 0;
}

int
shared_buffer_wunmap(
    shared_buffer_t *shared_buffer)
{
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (shared_buffer->write_addr == NULL) {
		LOG(LOG_LV_ERR, "shared buffer is not mapped in writing\n");
		return 1;
	}
	msync(shared_buffer->write_addr, shared_buffer->write_map_size, MS_SYNC);
	shared_buffer->dirty = 0;
	munmap(shared_buffer->write_addr, shared_buffer->write_map_size);
	shared_buffer->write_addr = NULL;

	return 0;
}

int
shared_buffer_lock_map(
    shared_buffer_t *shared_buffer,
    size_t map_size)
{
	shared_buffer_oflag_t oflag;

	if (shared_buffer == NULL ||
           (shared_buffer->open_oflag == SHBUF_OFL_WRITE && map_size <= 0) ||
           (shared_buffer->open_oflag == SHBUF_OFL_READ && map_size != 0)) {
		errno = EINVAL;
		return 1;
	}
	if (!shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is already locked\n");
		return 1;
	}
	/*
	 * if map_size == 0 then read operation
	 * if map_size > 0 then write operation
	 */
	if (map_size == 0) {
		oflag = SHBUF_OFL_READ;
	} else if(map_size > 0) {
		oflag = SHBUF_OFL_WRITE;
	} else {
		/* NOTREACHED */
		ABORT("unexpected map_size");
		goto fail;
	}
	if (shared_buffer_lock(shared_buffer, oflag)) {
		LOG(LOG_LV_ERR, "failed in lock shared buffer\n");
		goto fail;
	}
	if (map_size == 0) {
		if (shared_buffer_rmap(shared_buffer)) {
			LOG(LOG_LV_ERR, "failed in map shared buffer in reading\n");
			goto fail;
		}
	} else if (map_size > 0) {
		if (shared_buffer_wmap(shared_buffer, map_size)) {
			LOG(LOG_LV_ERR, "failed in map shared buffer in writing\n");
			goto fail;
		}
	} else {
		/* NOTREACHED */
		ABORT("unexpected map_size");
		goto fail;
	}

	return 0;
fail:

	if (shared_buffer->lock) {
		shared_buffer_unlock(shared_buffer);
	}

	return 1;
}

int
shared_buffer_unlock_unmap(
    shared_buffer_t *shared_buffer)
{
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (!shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opend\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	if (shared_buffer_unlock(shared_buffer)) {
		LOG(LOG_LV_ERR, "failed in unlock shared_buffer\n");
		return 1;
	}
	if (shared_buffer->read_addr != NULL) {
		if (shared_buffer_runmap(shared_buffer)) {
			LOG(LOG_LV_ERR, "failed in unmap shared_buffer in reading\n");
			return 1;
		}
	}
	if (shared_buffer->write_addr != NULL) {
		if (shared_buffer_wunmap(shared_buffer)) {
			LOG(LOG_LV_ERR, "failed in unmap shared_buffer in writing\n");
			return 1;
		}
	}

	return 0;
}

int
shared_buffer_read(
    shared_buffer_t *shared_buffer,
    char **data,
    size_t *data_size)
{
	size_t size;

	if (shared_buffer == NULL ||
	    data == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (!(shared_buffer->open_oflag & SHBUF_OFL_READ)) {
		LOG(LOG_LV_ERR, "shared buffer is not readable\n");
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opened\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	if (shared_buffer->read_addr == NULL) {
		LOG(LOG_LV_ERR, "shared buffer is not mapped\n");
		return 1;
	}
	size = (size_t)(*((uint64_t *)shared_buffer->read_addr));
	if (size == 0) {
		*data = NULL;
	} else {
		*data = (char *)(shared_buffer->read_addr + DATA_SIZE_LENGTH);
	}
	if (data_size) {
		*data_size = size;
	}

	return 0;
}

int
shared_buffer_write(
    shared_buffer_t *shared_buffer,
    const char *data,
    size_t data_size)
{
	uint64_t size;

	if (shared_buffer == NULL ||
	    data == NULL ||
	    data_size <= 0) {
		errno = EINVAL;
		return 1;
	}
	if (!(shared_buffer->open_oflag & SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "shared buffer is not writable\n");
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opened\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	if (!(shared_buffer->lock_oflag & SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "shared buffer is not writable locked\n");
		return 1;
	}
	if (shared_buffer->write_addr == NULL) {
		LOG(LOG_LV_ERR, "shared buffer is not mapped\n");
		return 1;
	}
	if (data_size > shared_buffer->write_map_size - DATA_SIZE_LENGTH) {
		LOG(LOG_LV_ERR, "writing data is too big\n");
		errno = ENOBUFS;
		return 1;
	}
	size = (uint64_t)data_size;
	memcpy(shared_buffer->write_addr, &size, DATA_SIZE_LENGTH);
	memcpy(shared_buffer->write_addr + DATA_SIZE_LENGTH, data, data_size);

	return 0;
}

int
shared_buffer_set_dirty(
    shared_buffer_t *shared_buffer)
{
	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (!(shared_buffer->open_oflag & SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "shared buffer is not writable\n");
		return 1;
	}
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "shared buffer is not opened\n");
		return 1;
	}
	if (!shared_buffer->lock) {
		LOG(LOG_LV_ERR, "shared buffer is not locked\n");
		return 1;
	}
	if (!(shared_buffer->lock_oflag & SHBUF_OFL_WRITE)) {
		LOG(LOG_LV_ERR, "shared buffer is not writable locked\n");
		return 1;
	}
	shared_buffer->dirty = 1;

	return 0;
}
