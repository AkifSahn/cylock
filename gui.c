#include <arpa/inet.h>
#include <glib.h>
#include <gtk/gtk.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "libspoof.h"

// Global Widgets
GtkWidget* text_view;
GtkWidget* entry;
GtkWidget* statusbar;
guint context_id;

char nickname[64] = "Anonymous";
gboolean connected = FALSE;
char node_mode[16] = "Client";

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

// Global
node_t node;

// GTK thread-safe message post
void gui_message_callback(const char* sender, const char* message, int message_len) {
	char* msg = g_strdup_printf("%s: %.*s", sender, message_len, message);
	g_idle_add(show_incoming_message, msg);
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

			if (start_udp_receiver(&node, RECV_PORT, gui_message_callback) == 0) {
				printf("Connected to network!");
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
		// Call your networking send function here!
		// send_message_to_network(nickname, msg);
		udp_send(msg, strlen(msg), nickname, "192.168.1.46", "255.255.255.255", 3131, 6969);

		// Add to chat display
		GtkTextBuffer* buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
		GtkTextIter end;
		gtk_text_buffer_get_end_iter(buffer, &end);

		char formatted_msg[512];
		snprintf(formatted_msg, sizeof(formatted_msg), "%s: %s\n", nickname, msg);
		gtk_text_buffer_insert(buffer, &end, formatted_msg, -1);

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
	strcpy(node_mode, "Client");
	char status[128];
	snprintf(status, sizeof(status), "Mode: Client");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, status);
}
void on_mode_gateway(GtkMenuItem* menuitem, gpointer user_data) {
	strcpy(node_mode, "Gateway");
	char status[128];
	snprintf(status, sizeof(status), "Mode: Gateway");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, status);
}

int main(int argc, char* argv[]) {
	gtk_init(&argc, &argv);

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

	// Chat Display (TextView)
	text_view = gtk_text_view_new();
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
	GtkWidget* scroll_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(scroll_win), text_view);
	gtk_box_pack_start(GTK_BOX(vbox), scroll_win, TRUE, TRUE, 5);

	// Message Entry and Send Button
	GtkWidget* hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 2);
	GtkWidget* send_btn = gtk_button_new_with_label("Send");
	gtk_box_pack_start(GTK_BOX(hbox), send_btn, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 2);

	g_signal_connect(send_btn, "clicked", G_CALLBACK(send_message), window);
	g_signal_connect(entry, "activate", G_CALLBACK(send_message), window);

	// Statusbar
	statusbar = gtk_statusbar_new();
	context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "status");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), context_id, "Disconnected. Mode: Client");
	gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);

	gtk_widget_show_all(window);
	gtk_main();

	return 0;
}
