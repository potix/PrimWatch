#ifndef COMMON_STRUCT_H
#define COMMON_STRUCT_H

typedef struct record_buffer record_buffer_t;
typedef struct map_element map_element_t;

struct record_buffer {
        int64_t ttl;
        int64_t record_priority;
        int64_t value_size;
        char value[0];
};

struct map_element {
        time_t ts;
        char value[0];
};

#endif
