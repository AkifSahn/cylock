#ifndef UTILS_H
#define UTILS_H

#include "libspoof.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <openssl/types.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// --- ID Cache ---
#define CACHE_SIZE 10

typedef struct id_cache {
	uint8_t i;
	uint32_t cache[CACHE_SIZE];
} id_cache;

void cache_add(id_cache* cache, uint32_t e);
int cache_search(const id_cache* cache, uint32_t e);
void cache_clear(id_cache* cache);

// --- ### ---

// --- Client Handling ---

typedef struct client client;

struct client {
	char name[NAME_LEN];
	char uid[UID_LEN];
	node_e type;
	time_t last_seen;
	char* pubkey_pem;
	EVP_PKEY* pubkey;
	client* next;
	client* prev;
};

typedef struct {
	struct client* head;
	struct client* tail;
	uint8_t size;
} ll_clients;

int has_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN]);
void add_new_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN], node_e type, const char* pubkey_pem);
client* find_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN]);
void remove_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN]);
void clear_clients(ll_clients* clients);

// --- ### ---

// --- Timer events ---

typedef struct timer_event {
	unsigned int u_delay;
	unsigned int count;
	void* (*handler)(void*);
	void* handler_arg;

	pthread_t thread;
} timer_event;

timer_event* new_timer_event(unsigned int u_delay, unsigned int count, void* (*handler)(void*), void* handler_arg);
void timer_event_stop(timer_event* event);
void* timer_thread(void* arg);

// --- ### ---

// --- Fragment handling ---

typedef struct {
	uint16_t id; // Packet id of fragments
	unsigned char* head; // Allocate at most num_frag * MAX_FRAG bytes
	int frag_received; // How many fragments we received
	size_t size;
} fragment;

typedef struct {
	fragment* fragments[10]; // 10 fragments at cache at most
	uint8_t size;
} fragments;

fragment* new_fragment(
	fragments* fragments, const unsigned char* frag_head, uint16_t id, int frag_num, int total_fragments, int size);
// --- Crypto ---

#define AES_KEYLEN 32 // 256 bits
#define AES_IVLEN 16 // For AES-CBC

unsigned char* encrypt_aes(
	const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, int* out_len);
int decrypt_aes(const unsigned char* ciphertext, int ciperhtext_len, const unsigned char* key, const unsigned char* iv,
	unsigned char* plaintext);

int encrypt_key_with_rsa(EVP_PKEY* pubkey, const unsigned char* aes_key, int keylen, unsigned char* encrypted_key);

int decrypt_key_with_rsa(
	EVP_PKEY* privkey, const unsigned char* encrypted_key, int encrypted_keylen, unsigned char* decrypted_key);

int node_generate_rsa_keypair(node_t* node);

EVP_PKEY* peer_pubkey_from_pem(const char* pubkey_pem);

// --- ### ---

#endif /* ifndef UTILS_H */
