#ifndef FINOVRA_MAIN_WINDOW_H
#define FINOVRA_MAIN_WINDOW_H

#include <gtk/gtk.h>

#include "database.h"

/* Crea y muestra la ventana principal con sus cuatro pestañas. */
void main_window_show(GtkApplication *app, Database *db);

#endif /* FINOVRA_MAIN_WINDOW_H */
