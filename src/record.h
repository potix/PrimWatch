#ifndef RECORD_H
#define RECORD_H

typedef struct record_buffer record_buffer_t;

struct record_buffer {
        int64_t ttl;
        int64_t record_priority;
        v4v6_addr_mask_t addr_mask;
        int64_t value_size;
        char value[0];
};

#endif
