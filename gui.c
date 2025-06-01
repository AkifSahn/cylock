#include <arpa/inet.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libspoof.h"

// Global Widgets
GtkWidget* text_view;
GtkWidget* entry;
GtkWidget* statusbar;
guint context_id;
GtkWidget* user_list;

char nickname[64] = "Anonymous";
gboolean connected = FALSE;
char node_mode[16] = "Client";

int num_gw_ips = 0;
char (*gateway_ips)[INET_ADDRSTRLEN];

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

#define CACHE_SIZE 10
typedef struct id_cache {
	uint8_t i;
	uint16_t cache[CACHE_SIZE];
} id_cache;

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

struct client {
	char name[NAME_LEN];
	node_e type;
	struct client* next;
	struct client* prev;
};

struct known_clients {
	struct client* head;
	struct client* tail;
	uint8_t size;
} known_clients;

void update_user_list() {
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
		printf("%s\n", curr->name);
		gtk_widget_set_halign(row, GTK_ALIGN_START);
		gtk_list_box_insert(GTK_LIST_BOX(user_list), row, -1);
		curr = curr->next;
	}
	gtk_widget_show_all(user_list);
}

int has_client(struct known_clients* clients, const char name[NAME_LEN]) {
	struct client* head = clients->head;
	while (head) {
		if (!strcmp(head->name, name)) {
			return 1;
		}
		head = head->next;
	}
	return 0;
}

void add_new_client(struct known_clients* clients, const char name[NAME_LEN], node_e type) {
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
	update_user_list();
}

void remove_client(struct known_clients* clients, const char name[NAME_LEN]) {
	printf("remove_client called for name: [%s]\n", name);
	struct client* head = clients->head;
	while (head) {
		printf("Comparing with: [%s]\n", head->name);
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
			update_user_list();
			return;
		}
		head = head->next;
	}
}

void clear_clients(struct known_clients* clients) {
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

// Global
node_t node;
id_cache cache;

// GTK thread-safe message post
void gui_message_callback(const header_t* header, const char* message, int message_len) {
	printf("%d\n", header->cl_flags);
	if (header->cl_flags != 0) {
		// Parse the flags
		if (header->cl_flags & CL_CONNECTED) {
			// Save username to known connections
			if (!has_client(&known_clients, header->name)) {
				add_new_client(&known_clients, header->name, header->node_type);
			}
			message = "New connection!";
			message_len = strlen(message);
		} else if (header->cl_flags & CL_DISCONNECTED) {
			// Remove username from known conenctions
			remove_client(&known_clients, header->name);
			message = "Disconnected!";
			message_len = strlen(message);
		} else if (header->cl_flags & CL_ALIVE) {
		}
	}

	if (node.type == N_GATEWAY && cache_search(&cache, header->id)) {
		return;
	}

	char* msg = g_strdup_printf("%s: %.*s", header->name, message_len, message);
	g_idle_add(show_incoming_message, msg);

	if (node.type == N_GATEWAY) {
		/*
		  If coming from outside, we also want to broadcast?
		  TODO: can't have more than 1 gw in same subnet with this
		*/
		cache_add(&cache, header->id);
		if (header->node_type == N_GATEWAY) {
			udp_send(
				message, message_len, header->name, header->node_type, header->id, "255.255.255.255", 6969, header->cl_flags);
		}
		for (int i = 0; i < num_gw_ips; ++i) {
			udp_send(message, message_len, header->name, header->node_type, header->id, gateway_ips[i], 6969, header->cl_flags);
		}
	}
}

// Placeholder: Call your networking C functions here!
void generate_keys() {
	// Implement your logic (maybe call your real C functions here)
	GtkWidget* dialog
		= gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Key pair generated (dummy action).");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
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

			// Set the node id
			srand(time(NULL));
			node.id = rand() % UINT16_MAX;

			cache_clear(&cache); // Reset the id cache
			if (start_udp_receiver(&node, RECV_PORT, gui_message_callback) == 0) {
				// Send a CL_ALIVE message
				usleep(100);
				udp_send(NULL, NULL, nickname, node.type, node.id, "192.168.1.255", RECV_PORT, CL_CONNECTED);
				node.id++;
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
    clear_clients(&known_clients);
    update_user_list();
}

void app_on_exit(GtkWidget* widget, gpointer data) { gtk_main_quit(); }

void show_about(GtkWindow* parent) {
	GtkWidget* dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
		"Anonymous P2P Chat\nDeveloper: YOUR NAME\nYeditepe University");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

// Send button callback
void send_message(GtkWidget* widget, gpointer data) {
	const gchar* msg = gtk_entry_get_text(GTK_ENTRY(entry));
	if (msg && strlen(msg) > 0) {
		if (!connected) {
			GtkWidget* dialog = gtk_message_dialog_new(
				GTK_WINDOW(data), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "Please connect to the network first!");
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
			return;
		}

		// If gateway, send the message to the other gateways on the gateway_ips.txt list.
		// Don't spoof the ip source when sending to other gateways
		if (node.type == N_GATEWAY) {
			for (int i = 0; i < num_gw_ips; ++i) {
				udp_send(msg, strlen(msg), nickname, node.type, node.id, gateway_ips[i], 6969, 0);
			}
			udp_send(msg, strlen(msg), nickname, node.type, node.id, "192.168.1.255", 6969, 0);
		} else {
			// TODO: Use spoofed ip
			udp_send_raw(msg, strlen(msg), nickname, node.type, node.id, "192.168.1.46", "192.168.1.255", 3131, 6969, 0);
		}

		node.id++;
		gtk_entry_set_text(GTK_ENTRY(entry), "");
	}
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
	gtk_box_pack_start(GTK_BOX(chat_vbox), hbox, FALSE, FALSE, 2);

	g_signal_connect(send_btn, "clicked", G_CALLBACK(send_message), window);
	g_signal_connect(entry, "activate", G_CALLBACK(send_message), window);

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
	update_user_list();
	gtk_main();

	return 0;
}
