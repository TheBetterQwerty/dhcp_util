#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#pragma pack(push, 1)

struct dhcp_header {
	uint8_t op;			// Message op code: 1=request, 2=reply
	uint8_t htype;		// Hardware type: 1=Ethernet
	uint8_t hlen;		// Hardware address length: 6 for Mac
	uint8_t hops;		// Ususually 0

	uint32_t xid;		// set to random
	uint16_t secs;		// Seconds since client started trying
	uint16_t flags;		// Flags (set to 0)

	uint32_t ciaddr;	// Client IP (0.0.0.0 for discover)
	uint32_t yiaddr;	// Server fills this
	uint32_t siaddr;	// Next server IP
	uint32_t giaddr;	// Relay agent IP

	uint8_t chaddr[16];	// Client hardware addrs (MAC + Padding)
	uint8_t sname[64];	// Opt sever host name
	uint8_t file[128];	// Boot file name
};

enum DHCP_PACKET_TYPE {
	DISCOVER = 1,
	OFFER = 2,
	REQUEST = 3,
	ACK = 5,
};

typedef struct {
	struct dhcp_header headers;
	uint8_t options[312];
} dhcp;

#pragma pack(pop)

dhcp* create_discover_packet();
dhcp* create_request_packet(const dhcp* offer_pkt);
void free_packet(dhcp* packet);

#endif
