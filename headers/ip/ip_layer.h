#ifndef IP_LAYER_H
#define IP_LAYER_H

#include <stdint.h>
#include <arpa/inet.h>
#include "../dhcp/dhcp_packet.h"

typedef struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint8_t ihl:4;
	uint8_t version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t version:4;
	uint8_t ihl:4;
#else
	#error "Byte order not supported"
#endif
	uint8_t  tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
} ip_headers;

uint16_t ip_checksum(uint16_t* pkt, int n);
void set_ip_layer(ip_headers* ip, uint8_t protocol);

#endif
