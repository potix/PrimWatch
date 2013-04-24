#ifndef ACCESSA_H
#define ACCESSA_H

#include "shared_buffer.h"

typedef struct accessa accessa_t;
typedef struct accessa_status accessa_status_t;
typedef struct accessa_status_group accessa_status_group_t;
typedef struct accessa_status_record accessa_status_record_t;

struct accessa_status_record {
	int record_weight;
};

struct accessa_status_group {
	int record_rr_idx;
	int group_weight;
	size_t records_data_size;
	char records_data[0];
};

struct accessa_status {
	int group_rr_idx;
	size_t groups_data_size;
	char groups_data[0];
};

struct accessa {
	shared_buffer_t *daemon_buffer;
	shared_buffer_t *accessa_buffer;
};

#endif
