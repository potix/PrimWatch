

#include "lookup.h"
#include "powerdns.h"

typedef enum request_type request_type_t;

enum request_type {
        REQ_TYPE_NATIVE = 1,
        REQ_TYPE_AXFR,
        REQ_TYPE_PING
};

int
powerdns_loop(
    accessa_t *accessa,
    int (*lookup_cb)(accessa_t *accessa,
        lookup_input_t *lookup_input,
        lookup_output_t *lookup_output)) 
{
	return 0;
}


