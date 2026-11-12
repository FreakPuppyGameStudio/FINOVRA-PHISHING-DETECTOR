#ifndef FINOVRA_UI_PAGES_H
#define FINOVRA_UI_PAGES_H

#include <gtk/gtk.h>

#include "database.h"

/* Resumen: gráficas de porcentajes por nivel de riesgo, totales y análisis recientes. */
GtkWidget *dashboard_new(Database *db);

/* Análisis de URLs: resultado con colores, cada análisis se guarda en el historial. */
GtkWidget *url_scanner_new(Database *db);

/* Análisis de correos: sesión, historial y búsqueda de campañas. */
GtkWidget *email_viewer_new(Database *db);

/* Método: explica cómo se calcula cada nivel de riesgo. */
GtkWidget *methodology_new(void);

#endif /* FINOVRA_UI_PAGES_H */
