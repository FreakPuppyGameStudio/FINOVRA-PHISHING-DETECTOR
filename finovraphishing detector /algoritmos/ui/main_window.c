#include "main_window.h"

#include "ui_pages.h"

void main_window_show(GtkApplication *app, Database *db)
{
    GtkWidget *window = gtk_application_window_new(app);
    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *notebook = gtk_notebook_new();

    gtk_window_set_title(GTK_WINDOW(window), "Finovra Phishing Detector");
    gtk_window_set_default_size(GTK_WINDOW(window), 1000, 680);
    gtk_window_set_titlebar(GTK_WINDOW(window), header);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             dashboard_new(db),
                             gtk_label_new("Resumen"));

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             url_scanner_new(db),
                             gtk_label_new("URL Scanner"));

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             email_viewer_new(db),
                             gtk_label_new("Email Analyzer"));

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             methodology_new(),
                             gtk_label_new("Método"));

    gtk_window_set_child(GTK_WINDOW(window), notebook);
    gtk_window_present(GTK_WINDOW(window));
}
