#include <gtk/gtk.h>

#include "database.h"
#include "main_window.h"

static void on_activate(GtkApplication *app, gpointer user_data)
{
    main_window_show(app, (Database *)user_data);
}

/* ~/.local/share/finovra-phishing/analisis.db (se crea si no existe) */
static gchar *database_path(void)
{
    gchar *dir = g_build_filename(g_get_user_data_dir(), "finovra-phishing", NULL);
    gchar *path;

    g_mkdir_with_parents(dir, 0700);
    path = g_build_filename(dir, "analisis.db", NULL);
    g_free(dir);
    return path;
}

int main(int argc, char **argv)
{
    Database *db = NULL;
    gchar *path = database_path();
    GtkApplication *app;
    int status;

    if (db_open(path, &db) != 0) {
        g_printerr("No se pudo abrir la base de datos: %s\n", path);
        g_free(path);
        return 1;
    }
    g_free(path);

    app = gtk_application_new("com.finovra.PhishingDetector", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), db);

    status = g_application_run(G_APPLICATION(app), argc, argv);

    g_object_unref(app);
    db_close(db);
    return status;
}
