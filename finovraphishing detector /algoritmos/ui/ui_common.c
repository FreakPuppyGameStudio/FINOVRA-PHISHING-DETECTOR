#include "ui_common.h"

#include <stdio.h>

/* Colores accesibles sobre fondo claro y oscuro */
#define COLOR_LOW       "#1e8e3e"
#define COLOR_SUSPICIOUS "#b06000"
#define COLOR_HIGH      "#c5221f"
#define COLOR_MUTED     "#6b6b6b"

static const char *risk_tag(UrlRisk risk)
{
    switch (risk) {
    case URL_RISK_LOW:
        return "tag-low";
    case URL_RISK_SUSPICIOUS:
        return "tag-suspicious";
    case URL_RISK_HIGH:
        return "tag-high";
    }
    return "tag-low";
}

static void insert_text(GtkTextBuffer *buf, const char *text, const char *tag)
{
    GtkTextIter end;
    gchar *safe = g_utf8_make_valid(text, -1);

    gtk_text_buffer_get_end_iter(buf, &end);
    if (tag)
        gtk_text_buffer_insert_with_tags_by_name(buf, &end, safe, -1, tag, NULL);
    else
        gtk_text_buffer_insert(buf, &end, safe, -1);
    g_free(safe);
}

void ui_setup_tags(GtkTextBuffer *buf)
{
    GtkTextTagTable *table = gtk_text_buffer_get_tag_table(buf);

    if (gtk_text_tag_table_lookup(table, "tag-high"))
        return;

    gtk_text_buffer_create_tag(buf, "tag-low",
                               "foreground", COLOR_LOW,
                               "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buf, "tag-suspicious",
                               "foreground", COLOR_SUSPICIOUS,
                               "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buf, "tag-high",
                               "foreground", COLOR_HIGH,
                               "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(buf, "tag-title",
                               "weight", PANGO_WEIGHT_BOLD,
                               "scale", 1.25, NULL);
    gtk_text_buffer_create_tag(buf, "tag-muted",
                               "foreground", COLOR_MUTED, NULL);
}

void ui_set_text(GtkTextBuffer *buf, const char *text)
{
    gchar *safe = g_utf8_make_valid(text, -1);

    gtk_text_buffer_set_text(buf, safe, -1);
    g_free(safe);
}

void ui_append(GtkTextBuffer *buf, const char *text)
{
    insert_text(buf, text, NULL);
}

void ui_append_title(GtkTextBuffer *buf, const char *text)
{
    insert_text(buf, text, "tag-title");
}

void ui_append_badge(GtkTextBuffer *buf, UrlRisk risk)
{
    char badge[64];

    snprintf(badge, sizeof badge, "● %s", url_risk_name(risk));
    insert_text(buf, badge, risk_tag(risk));
}

void ui_append_muted(GtkTextBuffer *buf, const char *text)
{
    insert_text(buf, text, "tag-muted");
}
