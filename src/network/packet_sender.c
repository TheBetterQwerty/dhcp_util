#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../headers/network/packet_sender.h"

int socket_init(struct sockaddr_in* server_addr) {
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		fprintf(stderr, "[!] Error: Socket creation failed\n");
		return -1;
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

	int set_val = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_NO_CHECK, &set_val, sizeof(set_val)) < 0) {
		perror("setsockopt UDP_CKSUM_REQUIRED failed");
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
	server_addr->sin_family = AF_INET;
	server_addr->sin_port = htons(DHCP_SERVER_PORT);
	server_addr->sin_addr.s_addr = htonl(INADDR_BROADCAST);

	return sockfd;
}

int packet_send(const uint8_t* pkt, size_t pkt_len, struct sockaddr_in* server_addr) {

	return 0;
}
