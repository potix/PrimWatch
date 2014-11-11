#ifndef COMMON_STRUCT_H
#define COMMON_STRUCT_H

typedef struct record_buffer record_buffer_t;
typedef struct map_element map_element_t;

enum record_type {
	RECORD_TYPE_FORWARD = 1,
	RECORD_TYPE_REVERSE,
};

struct record_buffer {
        int  wildcard;
        int64_t ttl;
        int64_t record_priority;
        int64_t value_size;
        char value[0];
};

struct map_element {
        char value[0];
};

#endif
