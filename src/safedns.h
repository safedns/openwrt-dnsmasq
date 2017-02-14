#ifndef SAFEDNS_GLOBAL_VARS_H_INCLUDED
#define SAFEDNS_GLOBAL_VARS_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#define SAFEDNS_log
//#define SAFEDNS_trace

void SAFEDNS_load_config();
size_t SAFEDNS_change_packet_and_port(char *proto_str, uint32_t ip, uint8_t *packet, size_t packet_len, unsigned short *port);

extern uint8_t SAFEDNS_enabled;

#endif // SAFEDNS_GLOBAL_VARS_H_INCLUDED
