#include "utils.h"
#include <bits/types.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

void add_new_client(ll_clients* clients, const char name[NAME_LEN], node_e type, const char* pubkey_pem) {
	if (has_client(clients, name)) {
		// Do not add duplicates
		return;
	}
	struct client* new = (struct client*)malloc(sizeof(struct client));
	memcpy(new->name, name, NAME_LEN * sizeof(char));
	new->type = type;
	new->next = NULL;
	new->prev = NULL;
	new->last_seen = time(NULL);
    new->pubkey_pem = pubkey_pem ? strdup(pubkey_pem) : NULL;
    new->pubkey = NULL;

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

client* find_client(ll_clients* clients, const char name[NAME_LEN]) {
	client* curr = clients->head;
	while (curr) {
		if (strcmp(curr->name, name) == 0) return curr;
		curr = curr->next;
	}
	return NULL;
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

// --- Timer events ---

// Initiates and starts a new timer event.
// TODO: Add cleanup functions.
timer_event* new_timer_event(unsigned int u_delay, unsigned int count, void* (*handler)(void*), void* handler_arg) {
	timer_event* event = (timer_event*)malloc(sizeof(timer_event));
	event->u_delay = u_delay;
	event->count = count;
	event->handler = handler;
	event->handler_arg = handler_arg;

	if (pthread_create(&event->thread, NULL, timer_thread, event) != 0) {
		free(event);
		return NULL;
	}

	return event;
}

void timer_event_stop(timer_event* event) {
	pthread_cancel(event->thread);
	pthread_join(event->thread, NULL);
	free(event);
}

void* timer_thread(void* arg) {
	timer_event* event = (timer_event*)arg;
	if (event->count == 0) {
		while (1) {
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			event->handler(event->handler_arg);
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
			usleep(event->u_delay);
		}
	} else {
		while (event->count > 0) {
			event->handler(event->handler_arg);
			event->count--;
			usleep(event->u_delay);
		}
	}
	return NULL;
}

// --- ### ---

// --- Crypto ---

// TODO: replace deprecated functions
int node_generate_rsa_keypair(node_t* node) {
	node->rsa_keypair = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	if (!node->rsa_keypair) return 0;

	BIO* mem = BIO_new(BIO_s_mem());
	PEM_write_bio_RSA_PUBKEY(mem, node->rsa_keypair);
	size_t pub_len = BIO_pending(mem);
	node->pubkey_pem = malloc(pub_len + 1);
	BIO_read(mem, node->pubkey_pem, pub_len);
	node->pubkey_pem[pub_len] = '\0';
	BIO_free(mem);

    return 1;
}

// --- ### ---
