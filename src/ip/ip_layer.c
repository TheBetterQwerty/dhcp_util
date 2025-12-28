#include <arpa/inet.h>
#include <netinet/udp.h>
#include <string.h>
#include "../../headers/dhcp/dhcp_packet.h"
#include "../../headers/ip/ip_layer.h"

uint16_t ip_checksum(uint16_t* pkt, int n) {
	uint32_t sum = 0;
	for (int i = 0; i < n; i++) sum += ntohl(pkt[i]);
	while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
	return htons(~sum);
}

void set_ip_layer(ip_headers* ip, uint8_t protocol) {
	if (!ip) return;
	memset(ip, 0, sizeof(ip_headers));

	ip->ihl = 5;
	ip->version = 4;

	ip->tos = 0;
	ip->tot_len = htons(sizeof(ip_headers) + sizeof(struct udphdr) + sizeof(dhcp));
	ip->id = htons(54321);
	ip->frag_off = htons(0);
	ip->ttl = 64;
	ip->protocol = protocol; // UDP
	ip->saddr = inet_addr("0.0.0.0"); // DHCP Client IP Spoof
	ip->daddr = inet_addr("255.255.255.255"); // Broadcast
	ip->check = ip_checksum((uint16_t*)ip, sizeof(ip_headers) / 2);
}
