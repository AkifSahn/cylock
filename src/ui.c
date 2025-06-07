#include <dirent.h>
#include <errno.h>
#include <gtk/gtk.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "glib.h"
#include "libspoof.h"
#include "utils.h"

// Global Widgets
GtkWidget* text_view;
GtkWidget* entry;
GtkWidget* statusbar;
guint context_id;
GtkWidget* user_list;

char nickname[NAME_LEN] = "Anonymous";
gboolean connected = FALSE;
char node_mode[16] = "Client";

int num_gw_ips = 0;
char (*gateway_ips)[INET_ADDRSTRLEN];

ll_clients known_clients;
node_t node;
id_cache cache;

char local_ip[INET_ADDRSTRLEN];
char broadcast_ip[INET_ADDRSTRLEN];

// in microsecond
#define NOTIFY_EVENT_TIMER 5000000
// In microsecond
#define PRUNE_EVENT_TIMER 60000000
// in second
#define PRUNE_STALE_CLIENT_DELAY 120

#define DEST_PORT 6969

// This function runs on the GTK main thread to update the chat window
gboolean show_incoming_message(gpointer data) {
	const char* msg = (const char*)data;
	GtkTextBuffer* buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
	GtkTextIter end;
	gtk_text_buffer_get_end_iter(buffer, &end);
	gtk_text_buffer_insert(buffer, &end, msg, -1);
	gtk_text_buffer_insert(buffer, &end, "\n", -1);
	g_free(data);
	return FALSE; // only run once
}

gboolean update_user_list(gpointer unused) {
	GList *children, *iter;

	children = gtk_container_get_children(GTK_CONTAINER(user_list));
	for (iter = children; iter != NULL; iter = g_list_next(iter)) {
		gtk_widget_destroy(GTK_WIDGET(iter->data));
	}
	g_list_free(children);

	// Now add the users
	struct client* curr = known_clients.head;
	while (curr) {
		GtkWidget* row = gtk_label_new(curr->name);
		gtk_widget_set_halign(row, GTK_ALIGN_START);
		gtk_list_box_insert(GTK_LIST_BOX(user_list), row, -1);
		curr = curr->next;
	}
	gtk_widget_show_all(user_list);
	return FALSE;
}

// [iv]
// [name_len:uint8_t][name][uint16_t:uid][encrytpted_len:uint16_t][encrypted_key].
// ...
// [ciphertext_len:uint32_t][ciphertext].
unsigned char* decrypt_incoming_message(const char* buffer, const int cipher_len, const char name[NAME_LEN],
	const uint8_t numkeys, EVP_PKEY* keypair, int* plaintextlen) {
	int pos = 0;
	unsigned char aes_iv[AES_IVLEN];
	memcpy(aes_iv, buffer, AES_IVLEN * sizeof(unsigned char));
	pos += AES_IVLEN * sizeof(unsigned char);

	unsigned char decrypted_key[AES_KEYLEN];
	bool found = false;
	for (int i = 0; i < numkeys; ++i) {
		uint8_t name_len;
		memcpy(&name_len, buffer + pos, sizeof(uint8_t));
		pos += sizeof(uint8_t);

		unsigned char* key_name = (unsigned char*)malloc((name_len + 1) * sizeof(unsigned char));
		memcpy(key_name, buffer + pos, name_len * sizeof(unsigned char));
		key_name[name_len] = '\0';
		pos += sizeof(unsigned char) * name_len;

		char uid[UID_LEN];
		memcpy(uid, buffer + pos, UID_LEN);
		pos += UID_LEN;

		// Compare key_name and name
		uint16_t encrypted_len;

		memcpy(&encrypted_len, buffer + pos, sizeof(uint16_t));
		pos += sizeof(uint16_t);

		unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_len * sizeof(unsigned char));
		memcpy(encrypted_key, buffer + pos, encrypted_len * sizeof(unsigned char));
		pos += encrypted_len * sizeof(unsigned char);
		if (strcmp((const char*)key_name, name) == 0 && memcmp(node.uid, uid, UID_LEN) == 0) {
			// This is our key, decrypt it
			found = true;

			int keylen = decrypt_key_with_rsa(keypair, encrypted_key, encrypted_len, decrypted_key);
			if (keylen < 0) {
				fprintf(stderr, "failed to decrypt the keypair!\n");
				free(key_name);
				free(encrypted_key);
				return NULL;
			}
		}
		free(encrypted_key);
		free(key_name);
	}

	if (!found) return NULL;

	// Now we are at the ciphertext part
	uint32_t ciphertext_len;
	memcpy(&ciphertext_len, buffer + pos, sizeof(uint32_t));
	pos += sizeof(uint32_t);

	unsigned char* ciphertext = malloc(ciphertext_len * sizeof(unsigned char));
	memcpy(ciphertext, buffer + pos, ciphertext_len * sizeof(unsigned char));
	pos += ciphertext_len * sizeof(unsigned char);

	unsigned char* plaintext = malloc(ciphertext_len * sizeof(unsigned char));
	*plaintextlen = decrypt_aes(ciphertext, ciphertext_len, decrypted_key, aes_iv, plaintext);

	free(ciphertext);

	return plaintext;
}

fragments fragments_cache;

// GTK thread-safe message post
void gui_message_callback(const header_t* header, const char* message, size_t message_len) {

	// Drop any packet that orignated from us
	if (!strcmp(header->name, node.name) && !memcmp(header->uid, node.uid, UID_LEN)) {
		return;
	}

	const char* payload;

	if (header->cl_flags & CL_FILE) {
		printf("receive:\n");
		printf("    from: %s\n", header->name);
		printf("    packet id: %d\n", header->id);
		printf("    fragment num: %d\n", header->frag_num);
		printf("    total fragments: %d\n", header->total_fragments);
	}

	if (header->total_fragments > 1) {
		fragment* frag = new_fragment(
			&fragments_cache, (unsigned char*)message, header->id, header->frag_num, header->total_fragments, header->size);
		if (frag) {
			payload = (char*)frag->head;
			message_len = frag->size;
			printf("Assembled all the fragments\n");
		} else {
			return;
		}
	} else {
		payload = message;
	}

	if (cache_search(&cache, header->id)) {
		return;
	}
	cache_add(&cache, header->id);

	char* msg_str = NULL;

	if (header->cl_flags & CL_CONNECTED) {
		// Save username to known connections
		if (!has_client(&known_clients, header->name, header->uid)) {
			// message is public key PEM string
			add_new_client(&known_clients, header->name, header->uid, header->node_type, payload);
			g_idle_add((GSourceFunc)update_user_list, NULL);
		}
		msg_str = g_strdup_printf("%s: %s", header->name, "New connection");
	} else if (header->cl_flags & CL_DISCONNECTED && strcmp(header->name, node.name)) {
		// Remove username from known conenctions
		remove_client(&known_clients, header->name, header->uid);
		g_idle_add((GSourceFunc)update_user_list, NULL);
		msg_str = g_strdup_printf("%s: %s", header->name, "Disconnected");
	} else if (header->cl_flags & CL_ALIVE) {
		client* c = find_client(&known_clients, header->name, header->uid);
		if (c) { // We already know about this client
			c->last_seen = time(NULL);
		} else { // We don't know about this client yet
			add_new_client(&known_clients, header->name, header->uid, header->node_type, payload);
			g_idle_add((GSourceFunc)update_user_list, NULL);
		}
	}

	// Message is encrypted
	if (header->cl_flags & CL_ENCRYPTED) {
		int msg_len = 0;
		// Try to decrypt the message
		unsigned char* dec_msg
			= decrypt_incoming_message(payload, message_len, node.name, header->num_key, node.keypair, &msg_len);
		if (dec_msg && msg_len > 0) {
			if (header->cl_flags & CL_FILE) {
				FILE* fp = fopen(header->filename, "wb");
				printf("    filename is '%s'\n", header->filename);
				if (!fp) {
					fprintf(stderr, "Failed to open file for writing\n");
					free(dec_msg);
					return;
				}
				if (fwrite(dec_msg, 1, msg_len, fp) <= 0) {
					fprintf(stderr, "Failed to write to file\n");
					free(dec_msg);
					fclose(fp);
					return;
				}
				fclose(fp);
			} else {
				msg_str = g_strdup_printf("%s: %.*s", header->name, msg_len, dec_msg);
			}
			free(dec_msg);
		} else {
			fprintf(stderr, "Failed to decrypt!\n");
			// Failed to decrypt a message
		}
	}

	if (msg_str) {
		g_idle_add(show_incoming_message, msg_str);
	}

	// Relay any incoming message
	if (node.type == N_GATEWAY) {
		if (header->node_type == N_GATEWAY && header->cl_flags & CL_RELAYED) { // Only broadcast to subnet if coming from relay
			udp_relay(payload, message_len, header, broadcast_ip, DEST_PORT, header->cl_flags ^ CL_RELAYED);
		}
		for (int i = 0; i < num_gw_ips; ++i) {
			udp_relay(payload, message_len, header, gateway_ips[i], DEST_PORT, header->cl_flags ^ CL_RELAYED);
		}
	}
}

void generate_keys() {
	GtkWidget* dialog
		= gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Key pair generated (dummy action).");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

timer_event* awake_event;
void* timer_awake(void* arg) {
	node_t* node = (node_t*)arg;
	int id = atomic_fetch_add(&node->id, 1);
	udp_send(node->pubkey_pem, strlen(node->pubkey_pem), node->name, node->uid, node->type, id, 0, broadcast_ip, DEST_PORT,
		CL_ALIVE, NULL);

	if (node->type == N_GATEWAY) {
		for (int i = 0; i < num_gw_ips; ++i) {
			udp_send(node->pubkey_pem, strlen(node->pubkey_pem), node->name, node->uid, node->type, id, known_clients.size,
				gateway_ips[i], DEST_PORT, CL_RELAYED | CL_ALIVE, NULL);
		}
	}
	return NULL;
}

// TODO: add thread safety for known_clients!! Race condition may occur!
timer_event* prune_event;
void* prune_stale_clients(void* arg) {
	time_t now = time(NULL);
	struct client* curr = known_clients.head;
	int updated = 0;
	while (curr) {
		struct client* next = curr->next; // Save next pointer as curr may be deleted
		if (difftime(now, curr->last_seen) > PRUNE_STALE_CLIENT_DELAY) {
			printf("Removing inactive client: %s\n", curr->name);
			remove_client(&known_clients, curr->name, curr->uid);
			updated = 1;
		}
		curr = next;
	}
	if (updated) g_idle_add((GSourceFunc)update_user_list, NULL); // Thread-safe GUI update
	return NULL;
}

void connect_to_network(GtkWindow* parent) {
	if (connected) {
		GtkWidget* dialog
			= gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Already connected!");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	GtkWidget* dialog = gtk_dialog_new_with_buttons(
		"Enter Nickname", parent, GTK_DIALOG_MODAL, "_OK", GTK_RESPONSE_OK, "_Cancel", GTK_RESPONSE_CANCEL, NULL);
	GtkWidget* content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	GtkWidget* entry_nick = gtk_entry_new();
	gtk_entry_set_placeholder_text(GTK_ENTRY(entry_nick), "Nickname");
	gtk_container_add(GTK_CONTAINER(content_area), entry_nick);
	gtk_widget_show_all(dialog);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
		const gchar* nick = gtk_entry_get_text(GTK_ENTRY(entry_nick));
		if (nick && strlen(nick) > 0) {
			strncpy(nickname, nick, sizeof(nickname) - 1);
			connected = TRUE;
			char status[128];
			snprintf(status, sizeof(status), "Connected as %s. Mode: %s", nickname, node_mode);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, status);

			strncpy(node.name, nickname, NAME_LEN);
			node.name[NAME_LEN - 1] = '\0';

			// Set the node id and generate keypair
			srand(time(NULL));
			atomic_store(&node.id, rand() % UINT16_MAX);

			if (!RAND_bytes((unsigned char*)node.uid, UID_LEN)) {
				fprintf(stderr, "Failed to generate a random UID\n");
				exit(1);
			}

			if (node.keypair) EVP_PKEY_free(node.keypair);
			if (node.pubkey_pem) free(node.pubkey_pem);
			node.keypair = NULL;
			node.pubkey_pem = NULL;
			if (!node_generate_rsa_keypair(&node)) {
				fprintf(stderr, "Failed to generate RSA keypair");
			}

			cache_clear(&cache); // Reset the id cache
			if (start_udp_receiver(&node, DEST_PORT, gui_message_callback) == 0) {
				// Send a CL_CONNECTED message
				awake_event = new_timer_event(NOTIFY_EVENT_TIMER, 0, timer_awake, &node);
				prune_event = new_timer_event(PRUNE_EVENT_TIMER, 0, prune_stale_clients, NULL);
				fragments_cache.size = 0;
				usleep(100);
				udp_send(node.pubkey_pem, strlen(node.pubkey_pem), node.name, node.uid, node.type, atomic_fetch_add(&node.id, 1),
					0, broadcast_ip, DEST_PORT, CL_CONNECTED, NULL);
			}
		}
	}
	gtk_widget_destroy(dialog);
}

void disconnect_from_network(GtkWindow* parent) {
	if (!connected) {
		GtkWidget* dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Not connected!");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}
	connected = FALSE;
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, "Disconnected.");
	stop_udp_receiver(&node);

	timer_event_stop(awake_event);
	timer_event_stop(prune_event);
	awake_event = NULL;
	prune_event = NULL;

	if (node.keypair) EVP_PKEY_free(node.keypair);
	if (node.pubkey_pem) free(node.pubkey_pem);
	node.keypair = NULL;
	node.pubkey_pem = NULL;

	clear_clients(&known_clients);
	g_idle_add((GSourceFunc)update_user_list, NULL);
}

void app_on_exit(GtkWidget* widget, gpointer data) { gtk_main_quit(); }

void show_about(GtkWindow* parent) {
	GtkWidget* dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
		"Anonymous P2P Chat\nDeveloper: YOUR NAME\nYeditepe University");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

/*
   [header]
   [iv]
   [name_len:uint8_t][name][char[UID_LEN]:uid][encrytpted_len:uint16_t][encrypted_key]
   ...
   [ciphertext_len:uint32_t][ciphertext]
*/
unsigned char* encrypt_outgoing_message(const char* msg, size_t msg_len, size_t* out_len) {
	// Generate AES key, encrypt message, encrypt AES key for each client
	unsigned char aes_key[AES_KEYLEN];
	unsigned char aes_iv[AES_IVLEN];

	if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(aes_iv, sizeof(aes_iv))) {
		fprintf(stderr, "Failed to generate secure random AES key!\n");
		return NULL;
	}

	int total_size = 0; // Total buffer size
	total_size += AES_IVLEN;
	total_size += sizeof(uint8_t) * known_clients.size; // name_len field
	total_size += UID_LEN; // UID field
	total_size += sizeof(uint16_t) * known_clients.size; // encrypted_len field
	total_size += sizeof(uint32_t); // ciphertext_len field

	// Needs to be dynamicly sized!
	int ciphertext_len;
	unsigned char* ciphertext = encrypt_aes((unsigned char*)msg, msg_len, aes_key, aes_iv, &ciphertext_len);
	total_size += ciphertext_len;

	if (!ciphertext || ciphertext_len <= 0) {
		fprintf(stderr, "Failed to encrypt message\n");
		return NULL;
	}

	unsigned char* encrypted_keys[known_clients.size];
	int encrypted_key_lens[known_clients.size];
	char* client_names[known_clients.size];
	char* client_uids[known_clients.size];

	client* cur = known_clients.head;
	int idx = 0;
	while (cur) {
		client_names[idx] = cur->name; // Shouldn't we use strcpy?
		total_size += strlen(cur->name);
		client_uids[idx] = cur->uid;
		encrypted_keys[idx] = malloc(EVP_PKEY_size(cur->pubkey));
		int elen = encrypt_key_with_rsa(cur->pubkey, aes_key, AES_KEYLEN, encrypted_keys[idx]);
		if (elen <= 0) {
			fprintf(stderr, "Failed to encrypt AES keys using RSA of '%s'\n", cur->name), free(encrypted_keys[idx]);
		}
		total_size += elen;

		encrypted_key_lens[idx] = elen;
		cur = cur->next;
		idx++;
	}

	unsigned char* buf = malloc(total_size * sizeof(unsigned char));
	int pos = 0;

	memcpy(buf + pos, aes_iv, AES_IVLEN);
	pos += AES_IVLEN;

	for (int i = 0; i < known_clients.size; ++i) {
		uint8_t name_len = strlen(client_names[i]);
		memcpy(buf + pos, &name_len, sizeof(name_len));
		pos += sizeof(name_len);
		memcpy(buf + pos, client_names[i], name_len);
		pos += name_len;
		memcpy(buf + pos, client_uids[i], UID_LEN);
		pos += UID_LEN;

		uint16_t eklen = encrypted_key_lens[i];
		memcpy(buf + pos, &eklen, sizeof(eklen));
		pos += sizeof(eklen);
		memcpy(buf + pos, encrypted_keys[i], eklen);
		pos += eklen;
	}

	uint32_t clen = ciphertext_len;
	memcpy(buf + pos, &clen, sizeof(clen));
	pos += sizeof(clen);
	memcpy(buf + pos, ciphertext, clen);
	pos += clen;

	free(ciphertext);
	for (int i = 0; i < known_clients.size; ++i)
		free(encrypted_keys[i]);

	*out_len = pos;
	return buf;
}

// Send button callback
void send_message(GtkWidget* widget, gpointer data) {
	const gchar* msg = gtk_entry_get_text(GTK_ENTRY(entry));
	char* msg_str = g_strdup_printf("You: %s", msg);
	g_idle_add(show_incoming_message, msg_str);
	if (msg && strlen(msg) > 0) {
		if (!connected) {
			GtkWidget* dialog = gtk_message_dialog_new(
				GTK_WINDOW(data), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "Please connect to the network first!");
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			return;
		}

		size_t total_len = 0;
		unsigned char* buf = encrypt_outgoing_message(msg, strlen(msg), &total_len);
		if (!buf || total_len <= 0) {
			fprintf(stderr, "Failed to encrypt outgoing message");
			return;
		}

		// If gateway, send the message to the other gateways on the gateway_ips.txt list.
		// Don't spoof the ip source when sending to other gateways
		if (node.type == N_GATEWAY) {
			uint16_t id = atomic_fetch_add(&node.id, 1);
			for (int i = 0; i < num_gw_ips; ++i) {
				udp_send((const char*)buf, total_len, node.name, node.uid, node.type, id, known_clients.size, gateway_ips[i],
					DEST_PORT, CL_RELAYED | CL_ENCRYPTED, NULL);
			}
			udp_send((const char*)buf, total_len, node.name, node.uid, node.type, id, known_clients.size, broadcast_ip, DEST_PORT,
				CL_ENCRYPTED, NULL);
		} else {
			// TODO: Use spoofed ip
			udp_send((const char*)buf, total_len, node.name, node.uid, node.type, atomic_fetch_add(&node.id, 1),
				known_clients.size, broadcast_ip, DEST_PORT, CL_ENCRYPTED, NULL);
		}

		gtk_entry_set_text(GTK_ENTRY(entry), "");
	}
}

void send_file_dialog(GtkWidget* widget, gpointer data) {
	if (!connected) {
		GtkWidget* dialog = gtk_message_dialog_new(
			NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "Please connect to the network first!");
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		return;
	}

	GtkWidget* dialog;
	dialog = gtk_file_chooser_dialog_new("Select File", GTK_WINDOW(data), GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel",
		GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		char* filepath;
		GtkFileChooser* chooser = GTK_FILE_CHOOSER(dialog);
		filepath = gtk_file_chooser_get_filename(chooser);

		// Read and send file
		FILE* fp = fopen(filepath, "rb");
		if (!fp) {
			fprintf(stderr, "Failed to open file - %s\n", strerror(errno));
			return;
		}

		fseek(fp, 0, SEEK_END);
		size_t filesize = ftell(fp);
		rewind(fp);

		unsigned char* filebuf = malloc(filesize);
		if (!filebuf) {
			fprintf(stderr, "Failed to allocate file buffer\n");
			fclose(fp);
			return;
		}
		fread(filebuf, 1, filesize, fp);
		fclose(fp);

		printf("total len of file: %zu\n", filesize);

		const char* filename = strrchr(filepath, '/');
		filename = filename ? filename + 1 : filepath;

		size_t total_len = 0;
		unsigned char* buf = encrypt_outgoing_message((char*)filebuf, filesize, &total_len);
		if (!buf || total_len <= 0) {
			fprintf(stderr, "Failed to encryprt file\n");
			g_free(filepath);
			return;
		}

		// If gateway, send the message to the other gateways on the gateway_ips.txt list.
		// Don't spoof the ip source when sending to other gateways
		if (node.type == N_GATEWAY) {
			uint16_t id = atomic_fetch_add(&node.id, 1);
			for (int i = 0; i < num_gw_ips; ++i) {
				udp_send((const char*)buf, total_len, node.name, node.uid, node.type, id, known_clients.size, gateway_ips[i],
					DEST_PORT, CL_RELAYED | CL_ENCRYPTED | CL_FILE, filename);
			}
			udp_send((const char*)buf, total_len, node.name, node.uid, node.type, id, known_clients.size, broadcast_ip, DEST_PORT,
				CL_ENCRYPTED | CL_FILE, filename);
		} else {
			// TODO: Use spoofed ip
			udp_send((const char*)buf, total_len, node.name, node.uid, node.type, atomic_fetch_add(&node.id, 1),
				known_clients.size, broadcast_ip, DEST_PORT, CL_ENCRYPTED | CL_FILE, filename);
		}

		g_free(filepath);
	}
	gtk_widget_destroy(dialog);
}

// Menu Callbacks
void on_generate_keys(GtkMenuItem* menuitem, gpointer user_data) { generate_keys(); }

void on_connect(GtkMenuItem* menuitem, gpointer user_data) { connect_to_network(GTK_WINDOW(user_data)); }

void on_disconnect(GtkMenuItem* menuitem, gpointer user_data) { disconnect_from_network(GTK_WINDOW(user_data)); }

void on_exit_menu(GtkMenuItem* menuitem, gpointer user_data) { app_on_exit(NULL, NULL); }

void on_about(GtkMenuItem* menuitem, gpointer user_data) { show_about(GTK_WINDOW(user_data)); }

// Node Mode callbacks
void on_mode_client(GtkMenuItem* menuitem, gpointer user_data) {
	node.type = N_CLIENT;

	strcpy(node_mode, "Client");
	char status[128];
	snprintf(status, sizeof(status), "Mode: Client");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, status);
}
void on_mode_gateway(GtkMenuItem* menuitem, gpointer user_data) {
	node.type = N_GATEWAY;

	strcpy(node_mode, "Gateway");
	char status[128];
	snprintf(status, sizeof(status), "Mode: Gateway");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, status);
}

void read_gateway_ips(char* filename) {
	FILE* f = fopen(filename, "r");
	if (!f) {
		perror("fopen");
		exit(1);
	}

	char line[INET_ADDRSTRLEN];

	while (fgets(line, sizeof(line), f)) {
		num_gw_ips++;
	}
	rewind(f);

	gateway_ips = malloc(num_gw_ips * INET_ADDRSTRLEN);
	if (!gateway_ips) {
		perror("malloc");
		fclose(f);
		exit(1);
	}

	int i = 0;
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = 0;
		strncpy(gateway_ips[i], line, 15);
		gateway_ips[i][15] = '\0';
		i++;
	}

	fclose(f);
}

int main(int argc, char* argv[]) {
	gtk_init(&argc, &argv);

	// Read known gateway ips from gw_ips.txt
	read_gateway_ips("gw_ips.txt");
	if (!get_host_ip_and_broadcast(local_ip, sizeof(local_ip), broadcast_ip, sizeof(broadcast_ip))) {
		fprintf(stderr, "Couldn't find a suitable network interface.\n");
		return 1;
	}

	GtkWidget* window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "Anonymous P2P Chat");
	gtk_window_set_default_size(GTK_WINDOW(window), 700, 500);

	g_signal_connect(window, "destroy", G_CALLBACK(app_on_exit), NULL);

	// VBox for main layout
	GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
	gtk_container_add(GTK_CONTAINER(window), vbox);

	// Menu Bar
	GtkWidget* menubar = gtk_menu_bar_new();

	// File Menu
	GtkWidget* file_menu = gtk_menu_new();
	GtkWidget* file_item = gtk_menu_item_new_with_label("File");
	GtkWidget* gen_keys = gtk_menu_item_new_with_label("Generate Keys");
	GtkWidget* connect = gtk_menu_item_new_with_label("Connect to network");
	GtkWidget* disconnect = gtk_menu_item_new_with_label("Disconnect from network");
	GtkWidget* exit_item = gtk_menu_item_new_with_label("Exit");
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), gen_keys);
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), connect);
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), disconnect);
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), gtk_separator_menu_item_new());
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), exit_item);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item), file_menu);

	g_signal_connect(gen_keys, "activate", G_CALLBACK(on_generate_keys), NULL);
	g_signal_connect(connect, "activate", G_CALLBACK(on_connect), window);
	g_signal_connect(disconnect, "activate", G_CALLBACK(on_disconnect), window);
	g_signal_connect(exit_item, "activate", G_CALLBACK(on_exit_menu), NULL);

	// Node Mode Menu
	GtkWidget* mode_menu = gtk_menu_new();
	GtkWidget* mode_item = gtk_menu_item_new_with_label("Node Mode");
	GtkWidget* mode_client = gtk_radio_menu_item_new_with_label(NULL, "Client");
	GtkWidget* mode_gateway = gtk_radio_menu_item_new_with_label_from_widget(GTK_RADIO_MENU_ITEM(mode_client), "Gateway");
	gtk_menu_shell_append(GTK_MENU_SHELL(mode_menu), mode_client);
	gtk_menu_shell_append(GTK_MENU_SHELL(mode_menu), mode_gateway);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(mode_item), mode_menu);

	g_signal_connect(mode_client, "activate", G_CALLBACK(on_mode_client), NULL);
	g_signal_connect(mode_gateway, "activate", G_CALLBACK(on_mode_gateway), NULL);

	// Help Menu
	GtkWidget* help_menu = gtk_menu_new();
	GtkWidget* help_item = gtk_menu_item_new_with_label("Help");
	GtkWidget* about = gtk_menu_item_new_with_label("About Developer");
	gtk_menu_shell_append(GTK_MENU_SHELL(help_menu), about);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(help_item), help_menu);

	g_signal_connect(about, "activate", G_CALLBACK(on_about), window);

	gtk_menu_shell_append(GTK_MENU_SHELL(menubar), file_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar), mode_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar), help_item);

	gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);

	//  hbox for chat and user list
	GtkWidget* hbox_main = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
	gtk_box_pack_start(GTK_BOX(vbox), hbox_main, TRUE, TRUE, 0);

	// left: Chat VBox
	GtkWidget* chat_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);

	// Chat Display (TextView)
	text_view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
	GtkWidget* scroll_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scroll_win), text_view);
	gtk_box_pack_start(GTK_BOX(chat_vbox), scroll_win, TRUE, TRUE, 5);

	// Message Entry and Send Button
	GtkWidget* hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 2);

	GtkWidget* send_btn = gtk_button_new_with_label("Send");
	gtk_box_pack_start(GTK_BOX(hbox), send_btn, FALSE, FALSE, 2);

	// NEW: Add file send button
	GtkWidget* send_file_btn = gtk_button_new_with_label("Send File");
	gtk_box_pack_start(GTK_BOX(hbox), send_file_btn, FALSE, FALSE, 2);

	gtk_box_pack_start(GTK_BOX(chat_vbox), hbox, FALSE, FALSE, 2);

	g_signal_connect(send_btn, "clicked", G_CALLBACK(send_message), window);
	g_signal_connect(entry, "activate", G_CALLBACK(send_message), window);
	// Connect new file send button
	g_signal_connect(send_file_btn, "clicked", G_CALLBACK(send_file_dialog), window);

	// Add chat_vbox (left side) to hbox_main
	gtk_box_pack_start(GTK_BOX(hbox_main), chat_vbox, TRUE, TRUE, 2);

	// right: User list
	user_list = gtk_list_box_new();
	gtk_widget_set_size_request(user_list, 180, -1);
	GtkWidget* user_list_frame = gtk_frame_new("Users");
	gtk_container_add(GTK_CONTAINER(user_list_frame), user_list);
	gtk_box_pack_start(GTK_BOX(hbox_main), user_list_frame, FALSE, FALSE, 2);

	// Statusbar
	statusbar = gtk_statusbar_new();
	context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "status");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, "Disconnected. Mode: Client");
	gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);

	gtk_widget_show_all(window);
	g_idle_add((GSourceFunc)update_user_list, NULL);

	gtk_main();

	return 0;
}
