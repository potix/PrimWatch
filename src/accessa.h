#ifndef ACCESSA_H
#define ACCESSA_H

#include "shared_buffer.h"

typedef struct accessa accessa_t;

struct accessa {
	shared_buffer_t *daemon_buffer;
};

#endif
