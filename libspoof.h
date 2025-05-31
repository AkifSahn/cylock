// libspoof.h
#ifndef LIBSPOOF_H
#define LIBSPOOF_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>

typedef enum {
	N_CLIENT,
	N_GATEWAY,
} node_e;

#define RECV_PORT 6969
#define RECV_BUF_SIZE 2048

#define NAME_LEN 32

typedef void (*message_callback_t)(const char* sender, node_e sender_type, const char* message, int message_len);

// Add to node_t
typedef struct Node {
	char name[NAME_LEN];
	node_e type;
	int sock_listen;
	pthread_t recv_thread;
	int recv_running;
	message_callback_t on_message; // function pointer for callback
} node_t;

typedef struct {
	uint16_t size; // Size of the payload.
	char name[NAME_LEN]; // nickname of the sender
	node_e node_type;
	uint8_t cl_bit; // control bit. If set, indicates the message is a control message
	uint32_t id; // Packet ID
	uint16_t frag_num; // Fragmentation number
	uint16_t total_fragments; // Total number of fragments
} header_t;

// Functions
void generate_random_ip(char* ip_str);

int start_udp_receiver(node_t* node, uint16_t listen_port, message_callback_t cb);
int stop_udp_receiver(node_t* node);

void udp_send_raw(const char* msg, uint16_t size, const char name[NAME_LEN], node_e node_type, char s_ip[INET_ADDRSTRLEN],
	char d_ip[INET_ADDRSTRLEN], uint16_t s_port, uint16_t d_port);
void udp_send(
	const char* msg, uint16_t size, const char name[NAME_LEN], node_e node_type, char d_ip[INET_ADDRSTRLEN], uint16_t d_port);

#endif
