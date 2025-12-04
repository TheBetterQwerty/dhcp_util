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

void append_option(uint8_t** ptr, uint8_t n, uint8_t* arr, uint8_t size) {
	if (!*ptr) return;
	*(*ptr)++ = n;
	*(*ptr)++ = size;
	memcpy(*ptr, arr, size);
	*ptr += size;
}

dhcp* create_discover_packet() {
	dhcp* packet = malloc(sizeof(dhcp));
	if (!packet) return NULL;
	memset(packet, 0, sizeof(dhcp));

	/* Headers */
	packet->headers.op = 1; // request
	packet->headers.htype = 1;
	packet->headers.hlen = 6;
	packet->headers.hops = 0;

	packet->headers.xid = ((uint32_t)rand() << 16) | ((uint32_t)rand() & 0xFFFF); // random 32 bit number
	packet->headers.secs = 0;
	packet->headers.flags = htons(0x8000); // broadcast flag

	packet->headers.ciaddr = 0;
	packet->headers.yiaddr = 0;
	packet->headers.siaddr = 0;
	packet->headers.giaddr = 0;

	memset(packet->headers.chaddr, 0, sizeof(packet->headers.chaddr));
	memset(packet->headers.sname, 0, sizeof(packet->headers.sname));
	memset(packet->headers.file, 0, sizeof(packet->headers.file));

	random_mac_address(packet->headers.chaddr);

	/* Options */
	uint8_t* ptr = packet->options;

	/* Magic cookies */
	memcpy(ptr, "\x63\x82\x53\x63", 4);
	ptr += 4;

	uint8_t msg = DISCOVER;
	append_option(&ptr, 53, &msg, 1);

	uint8_t temp_list[] = {1, 3, 6, 15, 28, 51, 58, 59};
	append_option(&ptr, 55, temp_list, sizeof(temp_list));

	*ptr++ = 0xFF;

	return packet;
}

dhcp* create_request_packet(const dhcp* offer_pkt) {
	if (!offer_pkt) return NULL;

	dhcp* packet = malloc(sizeof(dhcp));
	if (!packet) return NULL;

	memset(packet, 0, sizeof(dhcp));

	uint32_t server_id = 0;
	{
		const uint8_t* p = offer_pkt->options;
		p += 4; // skip magic cookies

		while (*p != 0xFF) {
			uint8_t code = p[0];
			uint8_t len = p[1];

			if (code == 54 && len == 4) {
				memcpy(&server_id, p + 2, 4);
				break;
			}

			p += 2 + len;
		}
	}

	if (server_id == 0) {
		free(packet);
		return NULL;
	}

	/* Headers */
	packet->headers.op = 1; // BOOTREQUEST
	packet->headers.htype = 1;
	packet->headers.hlen  = 6; // MAC length
    packet->headers.hops  = 0;

	packet->headers.xid = offer_pkt->headers.xid;
	packet->headers.secs = 0;
	packet->headers.flags = htons(0x8000); // broadcast flag

	packet->headers.ciaddr = 0;
	packet->headers.yiaddr = 0;
	packet->headers.siaddr = 0;
	packet->headers.giaddr = 0;

	memcpy(packet->headers.chaddr, offer_pkt->headers.chaddr, 6);

	/* Options Setting */
	uint8_t* ptr = packet->options;

	/* Magic cookies */
	memcpy(ptr, "\x63\x82\x53\x63", 4);
	ptr += 4;

	uint8_t client_id[7];
	client_id[0] = 1; // Ethernet
	memcpy(client_id + 1, offer_pkt->headers.chaddr, 6);
	append_option(&ptr, 61, client_id, sizeof(client_id));

	// Requested IP (from OFFER)
	append_option(&ptr, 50, (uint8_t*)&offer_pkt->headers.yiaddr, 4);

	// Server Identifier (from OFFER)
	append_option(&ptr, 54, (uint8_t*) &server_id, 4);

	// Parameter Request List (common options client wants)
	uint8_t param_req_list[] = {1, 3, 6, 15, 28, 51, 58, 59};
	append_option(&ptr, 55, param_req_list, sizeof(param_req_list));

	*ptr++ = 0xFF;

	return packet;
}

void free_packet(dhcp* packet) {
	if (packet) free(packet);
}
