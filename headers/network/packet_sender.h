#ifndef PACKET_SENDER_H
#define PACKET_SENDER_H

#include <stdint.h>
#include <stddef.h>

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

int socket_init(struct sockaddr_in* server_addr);
int packet_send(const uint8_t* pkt, size_t pkt_len, struct sockaddr_in* server_addr);

#endif
