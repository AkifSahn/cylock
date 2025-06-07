// libspoof.h
#ifndef LIBSPOOF_H
#define LIBSPOOF_H

#include <netinet/in.h>
#include <openssl/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
	N_CLIENT,
	N_GATEWAY,
} node_e;

#define MAX_FRAGMENT 1500// 48552 // 16184 // MAX len of our fragments
#define RECV_PORT 6969

#define NAME_LEN 32
#define FILENAME_LEN 32
#define UID_LEN 8

/*
 *      gw1 <--------> gw2 <------> c1,c2    gw3 <------> c3,c4
 *                      |                     |
 *                      +---------------------+
 */

// 1 -> ALIVE
// 2 -> DISCONNECTED
// ...
enum cl_e {
	CL_CONNECTED = 0x1, // Newly connected,
	CL_DISCONNECTED = 0x2, // Disconnected
	CL_ALIVE = 0x4, // Stil alive
	CL_RELAYED = 0x8, // Indicates that this packet is relayed
	CL_ENCRYPTED = 0x10, // Packet is encrypted
	CL_FILE = 0x20, // This is not a regulare message, but a file in base64 format
};

typedef struct {
	uint16_t size; // Size of the payload.
	char name[NAME_LEN]; // nickname of the sender
	char uid[UID_LEN]; // uid of the sender
	char filename[FILENAME_LEN];
	node_e node_type;
	uint8_t cl_flags; // control bit. If set, indicates the message is a control message
	uint16_t id; // Packet ID
	uint16_t frag_num; // Fragmentation number
	uint16_t total_fragments; // Total number of fragments
	uint8_t num_key; // How many encrypted AES keys in the payload
} header_t;

typedef void (*message_callback_t)(const header_t* header, const char* message, size_t message_len);

typedef struct Node {
	char name[NAME_LEN];
	char uid[UID_LEN];
	node_e type;
	atomic_uint_fast16_t id;
	int sock_listen;
	pthread_t recv_thread;
	int recv_running;
	message_callback_t on_message; // function pointer for callback

	EVP_PKEY* keypair;
	char* pubkey_pem;
} node_t;

// Functions
void generate_random_ip(char* ip_str);

int get_host_ip_and_broadcast(char* host_ip, size_t host_len, char* broadcast_ip, size_t broad_len);

int start_udp_receiver(node_t* node, uint16_t listen_port, message_callback_t cb);
int stop_udp_receiver(node_t* node);

// udp_send needs to know the senders name, and node_id of the sender.
void udp_send_raw(const char* msg, size_t size, const char name[NAME_LEN], const char uid[UID_LEN], node_e n_type, uint16_t id,
	uint8_t num_keys, char s_ip[INET_ADDRSTRLEN], char d_ip[INET_ADDRSTRLEN], uint16_t s_port, uint16_t d_port, enum cl_e flags,
	const char filename[FILENAME_LEN]);

void udp_send(const char* msg, size_t size, const char name[NAME_LEN], const char uid[UID_LEN], node_e n_type, uint16_t id,
	uint8_t num_keys, char d_ip[INET_ADDRSTRLEN], uint16_t d_port, enum cl_e flags, const char filename[FILENAME_LEN]);

void udp_relay(const char* msg, size_t size, const header_t* header, char d_ip[INET_ADDRSTRLEN], uint16_t d_port, enum cl_e flags);

#endif
