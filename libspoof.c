#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <assert.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "libspoof.h"

#define PCKT_LEN 8192 // Buffer length. Note - This isn't how much data we're actually sending.

/* Checksum function */
unsigned short csum(unsigned short* buf, int nwords) {
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--) {
		sum += *buf++;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

void generate_random_ip(char* ip_str) {
	srand((unsigned int)time(NULL));
	int oct1 = rand() % 256;
	int oct2 = rand() % 256;
	int oct3 = rand() % 256;
	int oct4 = rand() % 256;
	sprintf(ip_str, "%d.%d.%d.%d", oct1, oct2, oct3, oct4);
}

void* udp_receive_thread(void* arg) {
	node_t* node = (node_t*)arg;
	int sockfd;
	struct sockaddr_in servaddr, cliaddr;
	char buffer[RECV_BUF_SIZE];
	socklen_t len = sizeof(cliaddr);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("UDP receive socket failed");
		return NULL;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(node->sock_listen); // use .sock_listen as port

	if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		perror("UDP receive bind failed");
		close(sockfd);
		return NULL;
	}

	node->recv_running = 1;
	node->sock_listen = sockfd;

	while (node->recv_running) {
		ssize_t n = recvfrom(sockfd, buffer, RECV_BUF_SIZE - 1, 0, (struct sockaddr*)&cliaddr, &len);
		if (n > 0 && node->on_message) {
			header_t* custom = (header_t*)buffer;
			char* msg = (char*)(buffer + sizeof(header_t));
			int msg_len = n - sizeof(header_t);
			node->on_message(custom, msg, msg_len); // callback to GUI
		}
	}
	close(sockfd);
	return NULL;
}

int start_udp_receiver(node_t* node, uint16_t listen_port, message_callback_t cb) {
	if (node->recv_running) return 0; // Already running
	node->on_message = cb;
	node->sock_listen = listen_port;
	if (pthread_create(&node->recv_thread, NULL, udp_receive_thread, node) != 0) {
		perror("pthread_create failed");
		return -1;
	}
	return 0;
}

int stop_udp_receiver(node_t* node) {
	node->recv_running = 0;
	// Optionally, send a dummy datagram to self to unblock recvfrom if needed
    udp_send(NULL, NULL, node->name, node->type, node->id, "192.168.1.255", RECV_PORT, CL_DISCONNECTED);;
    if (!node->recv_running) return 0;
	pthread_join(node->recv_thread, NULL);
	node->sock_listen = -1;
	return 0;
}

// takes a  data with size data_size
// broadcasts to d_port with spoofed ip if randomize_ip is set
void udp_send_raw(const char* msg, uint16_t size, const char name[NAME_LEN], node_e n_type, uint16_t id,
	char s_ip[INET_ADDRSTRLEN], char d_ip[INET_ADDRSTRLEN], uint16_t s_port, uint16_t d_port, enum cl_e flags) {
	// Initialize variables.
	char buffer[PCKT_LEN];

	// Header pointers
	struct iphdr* iphdr = (struct iphdr*)buffer;
	struct udphdr* udphdr = (struct udphdr*)(buffer + sizeof(struct iphdr));
	header_t* custom_header = (header_t*)(buffer + sizeof(struct iphdr) + sizeof(struct udphdr));

	int sockfd;
	struct sockaddr_in sin;
	int one = 1;

	// Set packet buffer to 0's.
	memset(buffer, 0, PCKT_LEN);

	custom_header->size = htons(sizeof(header_t) + size);
	memcpy(custom_header->name, name, NAME_LEN);
	custom_header->node_type = n_type;
	custom_header->cl_flags = flags; // TODO: Needed for control messages
	custom_header->id = id; // TODO: Needed for fragmentation
	custom_header->frag_num = 0;
	custom_header->total_fragments = 0;
	char* pcktData = (char*)(buffer + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(header_t));

	memcpy(pcktData, msg, size);

	// Fill out source sockaddr in (IPv4, source address, and source port).
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(s_ip);
	sin.sin_port = htons(s_port);
	memset(&sin.sin_zero, 0, sizeof(sin.sin_zero));

	int payload_len = sizeof(header_t) + size; // header + data
	int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

	// Fill out the IP and UDP headers
	// IP Header.
	iphdr->ihl = 5;
	iphdr->version = 4;
	iphdr->tos = 16;
	iphdr->tot_len = htons(total_len); // Should be in network byte order!
	iphdr->id = htons(54321);
	iphdr->ttl = 64;
	iphdr->protocol = IPPROTO_UDP;
	iphdr->saddr = inet_addr(s_ip);
	iphdr->daddr = inet_addr(d_ip);

	// UDP Header.
	udphdr->uh_sport = htons(s_port);
	udphdr->uh_dport = htons(d_port);
	udphdr->len = htons(sizeof(struct udphdr) + payload_len);

	// IP Checksum.
	iphdr->check = csum((unsigned short*)buffer, sizeof(struct iphdr) + sizeof(struct udphdr));

	// Create the socket.
	sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

	// Check for socket error.
	if (sockfd <= 0) {
		fprintf(stderr, "Socket Error - %s\n", strerror(errno));
		perror("sockfd");

		exit(1);
	}

	// Let the socket know we want to pass our own headers.
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		fprintf(stderr, "Socket Option Error (Header Include) - %s\n", strerror(errno));
		perror("setsockopt");

		exit(1);
	}

	// Check for send error.
	if (sendto(sockfd, buffer, total_len, 0, (struct sockaddr*)&sin, sizeof(sin)) <= 0) {
		fprintf(stderr, "Error sending packet...\n\n");
		perror("sendto");
	}

	// Close socket.
	close(sockfd);
}

void udp_send(const char* msg, uint16_t size, const char name[NAME_LEN], node_e n_type, uint16_t id, char d_ip[INET_ADDRSTRLEN],
	uint16_t d_port, enum cl_e flags) {

	// Compose payload: header + message
	char buffer[1024];
	header_t* custom_header = (header_t*)buffer;

	memset(buffer, 0, sizeof(buffer));

	custom_header->size = htons(sizeof(header_t) + size);
	memcpy(custom_header->name, name, NAME_LEN);
	custom_header->node_type = n_type;
	custom_header->cl_flags = flags;
	custom_header->id = id;
	custom_header->frag_num = 0;
	custom_header->total_fragments = 0;

	char* pcktData = buffer + sizeof(header_t);
	memcpy(pcktData, msg, size);

	int payload_len = sizeof(header_t) + size;

	// Setup UDP socket
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	int broadcast = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
		perror("setsockopt");
		close(sockfd);
		return;
	}

	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(d_port);
	dest.sin_addr.s_addr = inet_addr(d_ip);

	// Send UDP datagram
	ssize_t sent = sendto(sockfd, buffer, payload_len, 0, (struct sockaddr*)&dest, sizeof(dest));
	if (sent < 0) {
		perror("sendto");
	}

	close(sockfd);
}
