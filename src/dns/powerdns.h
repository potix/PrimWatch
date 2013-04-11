#ifndef POWERDNS_H
#define POWERDNS_H

int powerdns_loop(
    accessa_t *accessa,
    int (*lookup_cb)(accessa_t *accessa,
        lookup_input_t *lookup_input,
        lookup_output_t *lookup_output));

#endif
