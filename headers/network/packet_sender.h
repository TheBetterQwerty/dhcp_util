#ifndef PACKET_SENDER_H
#define PACKET_SENDER_H

#include <stdint.h>

int socket_init(void);
int packet_send(const uint8_t* pkt, size_t pkt_len);

#endif
