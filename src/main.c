#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "../headers/packet.h"

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

void print_mac_addr(uint8_t* arr) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
        arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);
}

int main(void) {
	if (geteuid()) {
		fprintf(stderr, "[!] Error: This script requires elevated privilages!\n");
		return 1;
	}

	dhcp* packet = create_packet();
	if (!packet) {
		fprintf(stderr, "[!] Error: Creating packet for dhcp\n");
		return 1;
	}

	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		fprintf(stderr, "[!] Error: Socket creation failed\n");
		return 1;
	}

	int option_val = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option_val, sizeof(option_val)) < 0) {
		fprintf(stderr, "[!] Error: Couldn't set reuse options\n");
		close(sockfd);
		return 1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &option_val, sizeof(option_val)) < 0) {
		fprintf(stderr, "[!] Error: Couldn't set broadcast options\n");
		close(sockfd);
		return 1;
	}

	/* Bind client to port 68 (dhcp client port) */
	struct sockaddr_in client_addr = {0};
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(DHCP_CLIENT_PORT);
	client_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr*) &client_addr, sizeof(client_addr)) < 0) {
		fprintf(stderr, "[!] Error: Couldn't bind to network\n");
		close(sockfd);
		return 1;
	}

	/* Broadcast to dhcp server */
	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DHCP_SERVER_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	size_t pkt_len = sizeof(dhcp);

	if (sendto(sockfd, packet, pkt_len, 0,
				(struct sockaddr*) &server_addr, sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "[!] Error: Couldn't bind to network\n");
		close(sockfd);
		return 1;
	} else {
		printf("[+] Sent a dhcp packet with mac address: ");
		print_mac_addr(packet->headers.chaddr);
	}

	close(sockfd);
	free_packet(packet);
	return 0;
}
