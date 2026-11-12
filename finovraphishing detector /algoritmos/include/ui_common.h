#ifndef FINOVRA_UI_COMMON_H
#define FINOVRA_UI_COMMON_H

#include <gtk/gtk.h>

#include "url_analyzer.h"

/* Crea las etiquetas de color del búfer (solo la primera vez). */
void ui_setup_tags(GtkTextBuffer *buf);

/* Reemplaza todo el texto. */
void ui_set_text(GtkTextBuffer *buf, const char *text);

/* Agrega texto normal al final. */
void ui_append(GtkTextBuffer *buf, const char *text);

/* Agrega un título grande en negrita. */
void ui_append_title(GtkTextBuffer *buf, const char *text);

/* Agrega una insignia de color, por ejemplo "● Alto riesgo". */
void ui_append_badge(GtkTextBuffer *buf, UrlRisk risk);

/* Agrega texto apagado (secundario). */
void ui_append_muted(GtkTextBuffer *buf, const char *text);

#endif /* FINOVRA_UI_COMMON_H */
