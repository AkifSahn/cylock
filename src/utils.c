#include "utils.h"
#include "libspoof.h"
#include <bits/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
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

int has_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN]) {
	struct client* head = clients->head;
	while (head) {
		if (!strcmp(head->name, name) && !memcmp(head->uid, uid, UID_LEN)) {
			return 1;
		}
		head = head->next;
	}
	return 0;
}

void add_new_client(
	ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN], node_e type, const char* pubkey_pem) {
	if (has_client(clients, name, uid)) {
		// Do not add duplicates
		return;
	}
	struct client* new = (struct client*)malloc(sizeof(struct client));
	memcpy(new->name, name, NAME_LEN * sizeof(char));
	memcpy(new->uid, uid, UID_LEN);
	new->type = type;
	new->next = NULL;
	new->prev = NULL;
	new->last_seen = time(NULL);
	new->pubkey_pem = pubkey_pem ? strdup(pubkey_pem) : NULL;
	new->pubkey = NULL;

	if (pubkey_pem) {
		BIO* mem = BIO_new_mem_buf(pubkey_pem, -1);
		if (mem) {
			new->pubkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
			BIO_free(mem);
		}
		if (!new->pubkey) {
			free(new->pubkey_pem);
			free(new);
			return;
		}
	}

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

client* find_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN]) {
	client* curr = clients->head;
	while (curr) {
		if (strcmp(curr->name, name) == 0 && !memcmp(curr->uid, uid, UID_LEN)) return curr;
		curr = curr->next;
	}
	return NULL;
}

void remove_client(ll_clients* clients, const char name[NAME_LEN], const char uid[UID_LEN]) {
	struct client* head = clients->head;
	while (head) {
		if (!strcmp(head->name, name) && !memcmp(head->uid, uid, UID_LEN)) {
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

			if (head->pubkey) EVP_PKEY_free(head->pubkey);
			if (head->pubkey_pem) free(head->pubkey_pem);
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

		if (curr->pubkey) EVP_PKEY_free(curr->pubkey);
		if (curr->pubkey_pem) free(curr->pubkey_pem);
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

// input: plaintext, output: ciphertext, plaintext_len: length of plaintext
int encrypt_aes(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv,
	unsigned char* ciphertext) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1;
	}
	int len, ciphertext_len;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	ciphertext_len = len;

	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt_aes(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, const unsigned char* iv,
	unsigned char* plaintext) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int len, plaintext_len;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

int encrypt_key_with_rsa(EVP_PKEY* pubkey, const unsigned char* aes_key, int keylen, unsigned char* encrypted_key) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
	size_t outlen = EVP_PKEY_size(pubkey);

	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	if (EVP_PKEY_encrypt(ctx, encrypted_key, &outlen, aes_key, keylen) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);
	return outlen; // encrypted key length
}

int decrypt_key_with_rsa(
	EVP_PKEY* privkey, const unsigned char* encrypted_key, int encrypted_keylen, unsigned char* decrypted_key) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, NULL);
	if (!ctx) return -1;

	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	// 1st call to determine buffer length
	size_t outlen = 0;
	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_key, encrypted_keylen) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	// 2nd call to do actual decrypt
	if (EVP_PKEY_decrypt(ctx, decrypted_key, &outlen, encrypted_key, encrypted_keylen) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);
	return (int)outlen;
}

int node_generate_rsa_keypair(node_t* node) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) return 0;

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	if (EVP_PKEY_keygen(ctx, &(node->keypair)) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return 0;
	}

	EVP_PKEY_CTX_free(ctx);

	// Export public key to PEM
	BIO* mem = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_PUBKEY(mem, node->keypair)) {
		BIO_free(mem);
		return 0;
	}
	size_t pub_len = BIO_pending(mem);
	node->pubkey_pem = malloc(pub_len + 1);
	BIO_read(mem, node->pubkey_pem, pub_len);
	node->pubkey_pem[pub_len] = '\0';
	BIO_free(mem);

	return 1;
}

// caller must free with EVP_PKEY_free(pubkey)
EVP_PKEY* peer_pubkey_from_pem(const char* pubkey_pem) {
	BIO* mem = BIO_new_mem_buf(pubkey_pem, -1);
	EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
	BIO_free(mem);
	return pubkey; // caller must free with EVP_PKEY_free(pubkey)
}

// --- ### ---
