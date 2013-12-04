#ifndef RECORD_H
#define RECORD_H

typedef struct record_buffer record_buffer_t;

struct record_buffer {
        int64_t ttl;
        int64_t record_priority;
        int64_t value_size;
        char value[0];
};

#endif
