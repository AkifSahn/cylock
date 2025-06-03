#ifndef UTILS_H
#define UTILS_H

#include "libspoof.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <pthread.h>
#include <stdint.h>

// --- ID Cache ---
#define CACHE_SIZE 10

typedef struct id_cache {
	uint8_t i;
	uint16_t cache[CACHE_SIZE];
} id_cache;

void cache_add(id_cache* cache, uint16_t e);
int cache_search(const id_cache* cache, uint16_t e);
void cache_clear(id_cache* cache);

// --- ### ---

// --- Client Handling ---

typedef struct client client;

struct client {
	char name[NAME_LEN];
	node_e type;
	time_t last_seen;
	char* pubkey_pem;
	RSA* pubkey;
	client* next;
	client* prev;
};

typedef struct {
	struct client* head;
	struct client* tail;
	uint8_t size;
} ll_clients;

int has_client(ll_clients* clients, const char name[NAME_LEN]);
void add_new_client(ll_clients* clients, const char name[NAME_LEN], node_e type, const char* pubkey_pem);
client* find_client(ll_clients* clients, const char name[NAME_LEN]);
void remove_client(ll_clients* clients, const char name[NAME_LEN]);
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

// --- Crypto ---

int node_generate_rsa_keypair(node_t* node);

// --- ### ---

#endif /* ifndef UTILS_H */
