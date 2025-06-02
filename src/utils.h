#ifndef UTILS_H
#define UTILS_H

#include "libspoof.h"
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

struct client{
	char name[NAME_LEN];
	node_e type;
	client* next;
	client* prev;
};

typedef struct {
	struct client* head;
	struct client* tail;
	uint8_t size;
} ll_clients;

int has_client(ll_clients* clients, const char name[NAME_LEN]);
void add_new_client(ll_clients* clients, const char name[NAME_LEN], node_e type);
void remove_client(ll_clients* clients, const char name[NAME_LEN]);
void clear_clients(ll_clients* clients);

// --- ### ---

#endif /* ifndef UTILS_H */
