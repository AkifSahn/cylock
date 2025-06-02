#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


// --- ID Cache ---

void cache_add(id_cache* cache, uint16_t e) {
	if (cache->i >= CACHE_SIZE - 1) // rewind back
		cache->i = 0;

	cache->cache[cache->i++] = e;
}

int cache_search(const id_cache* cache, uint16_t e) {
	for (int i = 0; i < CACHE_SIZE; ++i) {
		if (cache->cache[i] == e) {
			return 1;
		}
	}
	return 0;
}

void cache_clear(id_cache* cache) {
	memset(cache->cache, 0, CACHE_SIZE * sizeof(uint16_t));
	cache->i = 0;
}

// --- ### ---

// --- Client Handling ---

int has_client(ll_clients* clients, const char name[NAME_LEN]) {
	struct client* head = clients->head;
	while (head) {
		if (!strcmp(head->name, name)) {
			return 1;
		}
		head = head->next;
	}
	return 0;
}

void add_new_client(ll_clients* clients, const char name[NAME_LEN], node_e type) {
	if (has_client(clients, name)) {
		// Do not add duplicates
		return;
	}
	struct client* new = (struct client*)malloc(sizeof(struct client));
	memcpy(new->name, name, NAME_LEN * sizeof(char));
	new->type = type;
	new->next = NULL;
	new->prev = NULL;

	clients->size++;
	// This is the first client
	if (!clients->head) {
		clients->head = new;
		clients->tail = new;
	} else {
		new->prev = clients->tail;
		clients->tail->next = new;
		clients->tail = new;
	}
	// update_user_list();
}

void remove_client(ll_clients* clients, const char name[NAME_LEN]) {
	struct client* head = clients->head;
	while (head) {
		if (!strcmp(head->name, name)) {
			if (head->prev) {
				head->prev->next = head->next;
			} else {
				clients->head = head->next; // head is being removed
			}
			if (head->next) {
				head->next->prev = head->prev;
			} else {
				clients->tail = head->prev; // tail is being removed
			}
			free(head);
			clients->size--;
			// update_user_list();
			return;
		}
		head = head->next;
	}
}

void clear_clients(ll_clients* clients) {
    struct client* curr = clients->head;
    while (curr) {
        struct client* next = curr->next;
        free(curr);
        curr = next;
    }
    clients->head = NULL;
    clients->tail = NULL;
    clients->size = 0;
}

// --- ### ---
