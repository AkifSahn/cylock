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

/*
 *      gw1 <--------> gw2 <------> c1,c2    gw3 <------> c3,c4
 *                      |                     |
 *                      +---------------------+
 */

// 1 -> ALIVE
// 2 -> DISCONNECTED
// ...
enum cl_e {
	CL_CONNECTED = 0x1, // Newly connected
	CL_DISCONNECTED = 0x2, // Disconnected
	CL_ALIVE = 0x4, // Stil alive
};

typedef struct {
	uint16_t size; // Size of the payload.
	char name[NAME_LEN]; // nickname of the sender
	node_e node_type;
	uint8_t cl_flags; // control bit. If set, indicates the message is a control message
	uint16_t id; // Packet ID
	uint16_t frag_num; // Fragmentation number
	uint16_t total_fragments; // Total number of fragments
} header_t;

typedef void (*message_callback_t)(const header_t* header, const char* message, int message_len);

// Add to node_t
typedef struct Node {
	char name[NAME_LEN];
	node_e type;
	uint16_t id;
	int sock_listen;
	pthread_t recv_thread;
	int recv_running;
	message_callback_t on_message; // function pointer for callback
} node_t;

// Functions
void generate_random_ip(char* ip_str);

int start_udp_receiver(node_t* node, uint16_t listen_port, message_callback_t cb);
int stop_udp_receiver(node_t* node);

// udp_send needs to know the senders name, and node_id of the sender.
void udp_send_raw(const char* msg, uint16_t size, const char name[NAME_LEN], node_e n_type, uint16_t id,
	char s_ip[INET_ADDRSTRLEN], char d_ip[INET_ADDRSTRLEN], uint16_t s_port, uint16_t d_port, enum cl_e flags);

void udp_send(const char* msg, uint16_t size, const char name[NAME_LEN], node_e n_type, uint16_t id, char d_ip[INET_ADDRSTRLEN],
	uint16_t d_port, enum cl_e flags);

#endif
