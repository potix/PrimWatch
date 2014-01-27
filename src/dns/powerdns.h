#ifndef POWERDNS_H
#define POWERDNS_H

int
powerdns_main(
    const char *question,
    const char *qname,
    const char *qclass,
    const char *qtype,
    const char *id,
    const char *remote_ip_address,
    accessa_t *accessa);

#endif
