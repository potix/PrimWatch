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
#include "shared_buffer.h"
#include "logger.h"

#define DATA_SIZE_LENGTH sizeof(uint64_t)

typedef enum oflag oflag_t;

enum oflag {
        OFL_READ = 1,
        OFL_WRITE,
        OFL_RDWR
};

struct shared_buffer {
	int fd;
	void *addr;
	size_t memsize;
	int lock;
	oflag_t oflag;
};

static int shared_buffer_touch(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    size_t memseize);
static int shared_buffer_sync(
    shared_buffer_t *shared_buffer);
static int shared_buffer_open(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    oflag_t oflag,
    size_t memsize);

static int
shared_buffer_touch(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    size_t memsize)
{
	int fd = -1;
	int lock_fl = 0;
	struct flock lock;

	ASSERT(shared_buffer != NULL);
	ASSERT(file_path != NULL);
	ASSERT(memsize > 0);
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
	if (ftruncate(fd, memsize)) {
		LOG(LOG_LV_ERR, "fail in truncate (%m)\n");
	}
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

static int
shared_buffer_sync(
    shared_buffer_t *shared_buffer)
{
	ASSERT(shared_buffer != NULL);
	ASSERT(shared_buffer->addr != NULL);
	msync(shared_buffer->addr, shared_buffer->memsize, MS_SYNC);

	return 0;
}

static int
shared_buffer_open(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    oflag_t oflag,
    size_t memsize)
{
	struct flock lock;
	mode_t mode;
	short type;
	int proto;
	size_t size;
	uint64_t *data_size_ptr;

	ASSERT(shared_buffer != NULL);
	ASSERT(file_path != NULL);
	ASSERT(oflag == OFL_WRITE || oflag == OFL_READ || oflag == OFL_RDWR);
	IFASSERT(oflag == OFL_WRITE, memsize > 0);

	if (oflag == OFL_READ) {
		mode = O_RDONLY;
		type = F_RDLCK;
		proto = PROT_READ;
		size = DATA_SIZE_LENGTH;
	} else if (oflag == OFL_WRITE || oflag == OFL_RDWR) {
		mode = O_RDWR;
		type = F_WRLCK;
		proto = PROT_WRITE;
		size = memsize + DATA_SIZE_LENGTH;
	} else {
		/* NOTREACHED */
		ABORT("unexpected flag");
	}
	if (oflag == OFL_WRITE || oflag == OFL_RDWR) {
		if (access(file_path, W_OK|R_OK)) {
			if (shared_buffer_touch(shared_buffer, file_path, size)) {
				goto fail;
			}
		}
	}
	memset(&lock, 0, sizeof(lock));
	lock.l_whence = SEEK_SET;
	lock.l_type = type;
	shared_buffer->fd = open(file_path, mode);
	if (shared_buffer->fd < 0) {
		LOG(LOG_LV_ERR, "failed in open shared file ((%m)\n");
		goto fail;
	}
	while (fcntl(shared_buffer->fd, F_SETLKW, &lock) != 0) {
		if (errno == EINTR) {
			continue;
		}
		LOG(LOG_LV_ERR, "failed in file lock %m\n");
		goto fail;
	}
	shared_buffer->lock = 1;
	if (oflag == OFL_READ || oflag == OFL_RDWR) {
		data_size_ptr = mmap(NULL, DATA_SIZE_LENGTH, proto, MAP_SHARED, shared_buffer->fd, 0);
		if (data_size_ptr == MAP_FAILED) {
			LOG(LOG_LV_ERR, "failin mmap %m\n");
			goto fail;
		}
		size += (size_t)(*data_size_ptr); 
		munmap(data_size_ptr, DATA_SIZE_LENGTH);
		shared_buffer->addr = mmap(NULL, size, proto, MAP_SHARED, shared_buffer->fd, 0);
		if (shared_buffer->addr == MAP_FAILED) {
			LOG(LOG_LV_ERR, "failin mmap %m\n");
			goto fail;
		}
	} else if (oflag == OFL_WRITE) {
		if (ftruncate(shared_buffer->fd, size)) {
			LOG(LOG_LV_ERR, "fail in truncate %m\n");
		}
		shared_buffer->addr = mmap(NULL, size, proto, MAP_SHARED, shared_buffer->fd, 0); 
		if (shared_buffer->addr == MAP_FAILED) {
			LOG(LOG_LV_ERR, "failin mmap %m\n");
			goto fail;
		}
	}
	shared_buffer->memsize = size;
	shared_buffer->oflag = oflag;

	return 0;

fail:
	if (shared_buffer->addr != NULL) {
		munmap(shared_buffer->addr, size);
		shared_buffer->addr = NULL;
	}
	if (shared_buffer->lock) {
		memset(&lock, 0, sizeof(lock));
		lock.l_whence = SEEK_SET;
		lock.l_type = F_UNLCK;
		fcntl(shared_buffer->fd, F_SETLK, &lock);
		shared_buffer->lock = 0;
	}
	if (shared_buffer->fd != -1) {
		close(shared_buffer->fd);
		shared_buffer->fd = -1;
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
	shared_buffer_close(shared_buffer);
	if (shared_buffer->fd != -1) {
		close(shared_buffer->fd);
	}
	free(shared_buffer);

	return 0;
}

int
shared_buffer_wopen(
    shared_buffer_t *shared_buffer,
    const char *file_path,
    size_t memsize)
{
	if (shared_buffer == NULL ||
	    file_path == NULL ||
	    memsize <= 0) {
		errno = EINVAL;
		return 1;
	}
	return shared_buffer_open(
	    shared_buffer,
	    file_path,
	    OFL_WRITE,
	    memsize);
}

int
shared_buffer_ropen(
    shared_buffer_t *shared_buffer,
    const char *file_path)
{
	if (shared_buffer == NULL ||
	    file_path == NULL) {
		errno = EINVAL;
		return 1;
	}
	return shared_buffer_open(
	    shared_buffer,
	    file_path,
	    OFL_READ,
	    0);
}

int
shared_buffer_rwopen(
    shared_buffer_t *shared_buffer,
    const char *file_path)
{
	if (shared_buffer == NULL ||
	    file_path == NULL) {
		errno = EINVAL;
		return 1;
	}
	return shared_buffer_open(
	    shared_buffer,
	    file_path,
	    OFL_RDWR,
	    0);
}

int
shared_buffer_close(
    shared_buffer_t *shared_buffer)
{
	struct flock lock;

	if (shared_buffer == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->fd == -1) {
		return 0; 
	}
	memset(&lock, 0, sizeof(lock));
	lock.l_whence = SEEK_SET;
	lock.l_type = F_UNLCK;
	fcntl(shared_buffer->fd, F_SETLK, &lock);
	shared_buffer->lock = 0;
	if (shared_buffer->oflag == OFL_WRITE) {
		shared_buffer_sync(shared_buffer);
	}
	munmap(shared_buffer->addr, shared_buffer->memsize);
	shared_buffer->addr = NULL;
	close(shared_buffer->fd);
	shared_buffer->fd = -1;

	return 0;
}

int
shared_buffer_read(
    shared_buffer_t *shared_buffer,
    char **data,
    size_t *data_size)
{
	uint64_t *size_ptr;

	if (shared_buffer == NULL ||
	    data == NULL ) {
		errno = EINVAL;
		return 1;
	}
	if (shared_buffer->addr == NULL) {
		*data = NULL;
		*data_size = 0;
		return 0;
	}
	*data = (shared_buffer->addr + DATA_SIZE_LENGTH);
	size_ptr = shared_buffer->addr;
	if (data_size) {
		*data_size = (size_t)(*size_ptr);
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
	if (shared_buffer->addr == NULL) {
		return 0;
	}
	if (shared_buffer->oflag == OFL_RDWR) {
		if (ftruncate(shared_buffer->fd, data_size + DATA_SIZE_LENGTH)) {
			LOG(LOG_LV_ERR, "fail in truncate (%m)\n");
		}
		shared_buffer->memsize = data_size + DATA_SIZE_LENGTH;
	} else {
		if (data_size > shared_buffer->memsize - DATA_SIZE_LENGTH) {
			errno = ENOBUFS;
			return 1;
		}
	}
	size = (uint64_t)data_size;
	memcpy(shared_buffer->addr, &size, DATA_SIZE_LENGTH);
	memcpy(shared_buffer->addr + DATA_SIZE_LENGTH, data, data_size);

	return 0;
}
