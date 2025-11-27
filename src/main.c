#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../headers/packet.h"

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DELAY 1

struct argument {
	int integer_part;
	char* char_pointer;
};

void capture_packets(
	u_char* user __attribute__((unused)),
	const struct pcap_pkthdr* pkt_header __attribute__((unused)),
	const u_char* packet
) {
	const struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
	int ip_len = ip->ip_hl * 4;

	const dhcp* offer_packet = (dhcp*) (packet + sizeof(struct ether_header) + ip_len + sizeof(struct udphdr));
	if (offer_packet->headers.op != 2) return;

	const uint8_t* mac = offer_packet->headers.chaddr;
	struct in_addr offered_ip;
	offered_ip.s_addr = offer_packet->headers.yiaddrs;

	// magic cookie check
	if (memcmp(offer_packet->options, "\x63\x82\x53\x63", 4)) return;

	printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x -> IP: %s\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		inet_ntoa(offered_ip)
	);

}

void* read_packet(void* _args) {
	struct argument* args = _args;
	char* dev = args->char_pointer;

	if (!dev) return NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevsp = NULL;

	if (pcap_findalldevs(&alldevsp, errbuf) < 0) {
		fprintf(stderr, "[!] Error: %s\n", errbuf);
		return NULL;
	}

	pcap_t* handle = pcap_open_live(dev, 65535, 0, 1000, errbuf);
	if (!handle) {
		fprintf(stderr, "[!] Error: opening %s\n", dev);
		goto cleanup;
	}

	printf("[*] Sniffing for dhcp packets using %s\n", dev);

	struct bpf_program fp;
	char* filter = "udp port 67 or udp port 68";

	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "[!] Error: Couldn't parse filter: %s\n", pcap_geterr(handle));
		goto cleanup;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "[!] Error: Couldn't install filter: %s\n", pcap_geterr(handle));
		goto cleanup;
	}

	if (pcap_loop(handle, args->integer_part, capture_packets, NULL) < 0) {
		fprintf(stderr, "[!] Error: capturing packet!\n");
		goto cleanup;
	}

cleanup:
	if (alldevsp) pcap_freealldevs(alldevsp);
	pcap_freecode(&fp);
	if (handle) pcap_close(handle);
	printf("[#] Exitting ... \n");
	return NULL;
}

void send_packets(int cnt) {
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		fprintf(stderr, "[!] Error: Socket creation failed\n");
		return;
	}

	int option_val = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option_val, sizeof(option_val)) < 0) {
		fprintf(stderr, "[!] Error: Couldn't set reuse options\n");
		close(sockfd);
		return;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &option_val, sizeof(option_val)) < 0) {
		fprintf(stderr, "[!] Error: Couldn't set broadcast options\n");
		close(sockfd);
		return;
	}

	/* Bind client to port 68 (dhcp client port) */
	struct sockaddr_in client_addr = {0};
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(DHCP_CLIENT_PORT);
	client_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr*) &client_addr, sizeof(client_addr)) < 0) {
		fprintf(stderr, "[!] Error: Couldn't bind to network\n");
		close(sockfd);
		return;
	}

	/* Broadcast to dhcp server */
	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DHCP_SERVER_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);


	while (cnt) {
		dhcp* packet = create_packet();
		if (!packet) {
			fprintf(stderr, "[!] Error: Creating packet for dhcp\n");
			break;
		}

		if (sendto(sockfd, packet, sizeof(dhcp), 0,
			 (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0)
		{
			fprintf(stderr, "[!] Error: Couldn't bind to network\n");
			close(sockfd);
			break;
		}

		cnt--;
		free_packet(packet);
		sleep(DELAY);
	}

	close(sockfd);
}

int main(int args, char** argv) {
	if (geteuid()) {
		fprintf(stderr, "[!] Error: This script requires elevated privilages!\n");
		return 1;
	}

	if (args < 3) {
		fprintf(stderr, "[!] Usage: %s --packets <number>\n", argv[0]);
		return 1;
	}

	int packets_to_send = !strcmp(argv[1], "--packets") ? atoi(argv[2]) : 0;

	pthread_t listener_thread;

	struct argument arguments = {0};
	arguments.integer_part = packets_to_send;
	arguments.char_pointer = "wlan0";

	pthread_create(&listener_thread, NULL, read_packet, (void*) &arguments);

	send_packets(packets_to_send);

	pthread_join(listener_thread, NULL);
	printf("[+] Sent %d packets to the dhcp server\n", packets_to_send);
	return 0;
}
