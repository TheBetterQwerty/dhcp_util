#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "../headers/packet.h"

void random_mac_address(uint8_t* addr) {
	srand(time(NULL));

	for (int i = 0; i < 6; i++) addr[i] = rand() & 0xFF;

	addr[0] &= ~0x01;  // Clear multicast bit (ensure unicast)
	addr[0] |= 0x02;   // Set locally-administered bit
}

dhcp* create_packet() {
	dhcp* packet = malloc(sizeof(dhcp));
	if (!packet) return NULL;

	/* Headers */
	packet->headers.op = 1;
	packet->headers.htype = 1;
	packet->headers.hlen = 6;
	packet->headers.hops = 0;

	packet->headers.xid = ((uint32_t)rand() << 16) | ((uint32_t)rand() & 0xFFFF); // random 32 bit number
	packet->headers.secs = 0;
	packet->headers.flags = htons(0x8000); // broadcast flag

	packet->headers.ciaddr = 0;
	packet->headers.yiaddrs = 0;
	packet->headers.siaddrs = 0;
	packet->headers.giaddrs = 0;

	memset(packet->headers.chaddr, 0, sizeof(packet->headers.chaddr));
	memset(packet->headers.sname, 0, sizeof(packet->headers.sname));
	memset(packet->headers.file, 0, sizeof(packet->headers.file));

	random_mac_address(packet->headers.chaddr);

	/* Options */
	uint8_t* ptr = packet->options;

	/* Magic cookies */
	memcpy(ptr, "\x63\x82\x53\x63", 4);
	ptr += 4;

	*ptr++ = 53;
	*ptr++ = 1;
	*ptr++ = 1; // discover

	uint8_t temp_list[] = {1, 3, 6, 15, 28, 51, 58, 59};
	*ptr++ = 55;
	*ptr++ = sizeof(temp_list);
	memcpy(ptr, temp_list, sizeof(temp_list));
	ptr += sizeof(temp_list);

	*ptr++ = 0xFF;

	return packet;
}

void free_packet(dhcp* packet) {
	if (packet) free(packet);
}
