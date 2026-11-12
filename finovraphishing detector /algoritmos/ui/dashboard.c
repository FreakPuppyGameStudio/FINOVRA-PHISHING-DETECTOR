#include <stdio.h>

#include "ui_common.h"
#include "ui_pages.h"

typedef struct {
    int64_t low;
    int64_t suspicious;
    int64_t high;
} Split;

typedef struct {
    Database *db;
    GtkWidget *stats_label;
    GtkWidget *summary_label;
    GtkWidget *chart;
    GtkWidget *status_label;
    GtkTextBuffer *buffer;
    Split url_split;
    Split email_split;
} DashboardUi;

static int64_t split_total(const Split *s)
{
    return s->low + s->suspicious + s->high;
}

static int percent_of(int64_t value, int64_t total)
{
    if (total <= 0)
        return 0;
    return (int)((value * 100 + total / 2) / total);
}

/* Colores de los niveles: mismos tonos que las insignias de texto */
static void set_level_color(cairo_t *cr, UrlRisk risk)
{
    switch (risk) {
    case URL_RISK_LOW:
        cairo_set_source_rgb(cr, 0.12, 0.56, 0.24);
        break;
    case URL_RISK_SUSPICIOUS:
        cairo_set_source_rgb(cr, 0.85, 0.46, 0.02);
        break;
    case URL_RISK_HIGH:
        cairo_set_source_rgb(cr, 0.77, 0.13, 0.12);
        break;
    }
}

/* Texto centrado horizontalmente en x, con la línea base en y */
static void show_centered(cairo_t *cr, double x, double y, const char *text)
{
    cairo_text_extents_t ext;

    cairo_text_extents(cr, text, &ext);
    cairo_move_to(cr, x - ext.width / 2.0 - ext.x_bearing, y);
    cairo_show_text(cr, text);
}

/* Anillo con un segmento por nivel; el centro muestra el total */
static void draw_donut(cairo_t *cr, double cx, double cy, double r_out, double r_in,
                       const char *title, const Split *s)
{
    int64_t total = split_total(s);
    int64_t counts[3] = {s->low, s->suspicious, s->high};
    UrlRisk levels[3] = {URL_RISK_LOW, URL_RISK_SUSPICIOUS, URL_RISK_HIGH};
    double angle = -G_PI / 2.0;
    char number[32];

    /* Título */
    cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 15);
    show_centered(cr, cx, cy - r_out - 14, title);

    if (total <= 0) {
        cairo_set_source_rgb(cr, 0.88, 0.88, 0.88);
        cairo_new_path(cr);
        cairo_arc(cr, cx, cy, r_out, 0, 2 * G_PI);
        cairo_arc_negative(cr, cx, cy, r_in, 2 * G_PI, 0);
        cairo_close_path(cr);
        cairo_fill(cr);

        cairo_set_source_rgb(cr, 0.45, 0.45, 0.45);
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 12);
        show_centered(cr, cx, cy + 4, "Sin datos");
        return;
    }

    for (size_t i = 0; i < 3; i++) {
        double sweep;

        if (counts[i] <= 0)
            continue;
        sweep = 2.0 * G_PI * (double)counts[i] / (double)total;

        cairo_new_path(cr);
        cairo_arc(cr, cx, cy, r_out, angle, angle + sweep);
        cairo_arc_negative(cr, cx, cy, r_in, angle + sweep, angle);
        cairo_close_path(cr);
        set_level_color(cr, levels[i]);
        cairo_fill(cr);

        angle += sweep;
    }

    /* Centro: total analizado */
    snprintf(number, sizeof number, "%lld", (long long)total);
    cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 22);
    show_centered(cr, cx, cy + 2, number);

    cairo_set_source_rgb(cr, 0.45, 0.45, 0.45);
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 11);
    show_centered(cr, cx, cy + 18, "analizados");
}

/* Leyenda: cuadro de color, nivel, cantidad y porcentaje */
static void draw_legend(cairo_t *cr, double x, double y, const Split *s)
{
    int64_t counts[3] = {s->low, s->suspicious, s->high};
    UrlRisk levels[3] = {URL_RISK_LOW, URL_RISK_SUSPICIOUS, URL_RISK_HIGH};
    int64_t total = split_total(s);
    char text[96];

    for (size_t i = 0; i < 3; i++) {
        set_level_color(cr, levels[i]);
        cairo_rectangle(cr, x, y + i * 22 - 10, 12, 12);
        cairo_fill(cr);

        cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
        cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 12);
        snprintf(text, sizeof text, "%s: %lld (%d%%)",
                 url_risk_name(levels[i]), (long long)counts[i], percent_of(counts[i], total));
        cairo_move_to(cr, x + 20, y + i * 22);
        cairo_show_text(cr, text);
    }
}

static void draw_chart(GtkDrawingArea *area, cairo_t *cr, int width, int height, gpointer user_data)
{
    DashboardUi *ui = user_data;
    double w = width;

    (void)area;
    (void)height;

    /* Dos anillos lado a lado */
    draw_donut(cr, w * 0.25, 120, 84, 54, "URLs", &ui->url_split);
    draw_donut(cr, w * 0.75, 120, 84, 54, "Correos", &ui->email_split);

    draw_legend(cr, w * 0.25 - 80, 236, &ui->url_split);
    draw_legend(cr, w * 0.75 - 80, 236, &ui->email_split);
}

/* Frase en lenguaje sencillo con los porcentajes actuales */
static void format_summary(char *out, size_t size, const char *name, const Split *s)
{
    int64_t total = split_total(s);

    if (total <= 0) {
        snprintf(out, size, "%s: todavía no hay análisis.", name);
        return;
    }
    snprintf(out, size,
             "%s: %d%% bajo riesgo, %d%% sospechosos, %d%% alto riesgo (de %lld).",
             name,
             percent_of(s->low, total),
             percent_of(s->suspicious, total),
             percent_of(s->high, total),
             (long long)total);
}

static void refresh(DashboardUi *ui)
{
    DbStats st;
    DbRiskBreakdown b;
    char stats[512];
    char summary[512];
    char line[256];
    char recent[4096];

    if (db_stats(ui->db, &st) == 0) {
        snprintf(stats, sizeof stats,
                 "URLs analizadas: %lld\n"
                 "Correos analizados: %lld\n"
                 "Enlaces guardados de correos: %lld\n"
                 "Análisis de alto riesgo: %lld\n"
                 "Campañas guardadas: %lld",
                 (long long)st.url_scans, (long long)st.emails,
                 (long long)st.email_urls, (long long)st.high_risk,
                 (long long)st.campaigns);
    } else {
        snprintf(stats, sizeof stats, "No se pudieron leer las estadísticas.");
    }
    gtk_label_set_text(GTK_LABEL(ui->stats_label), stats);

    if (db_risk_breakdown(ui->db, &b) == 0) {
        ui->url_split.low = b.url_low;
        ui->url_split.suspicious = b.url_suspicious;
        ui->url_split.high = b.url_high;
        ui->email_split.low = b.email_low;
        ui->email_split.suspicious = b.email_suspicious;
        ui->email_split.high = b.email_high;
    }

    format_summary(summary, sizeof summary, "URLs", &ui->url_split);
    snprintf(line, sizeof line, "%s\n", summary);
    format_summary(summary, sizeof summary, "Correos", &ui->email_split);
    {
        char both[768];

        snprintf(both, sizeof both, "%s\n%s", line, summary);
        gtk_label_set_text(GTK_LABEL(ui->summary_label), both);
    }

    gtk_widget_queue_draw(ui->chart);

    ui_set_text(ui->buffer, "");
    if (db_recent_text(ui->db, 10, recent, sizeof recent) == 0 && recent[0] != '\0')
        ui_append(ui->buffer, recent);
    else
        ui_append_muted(ui->buffer, "Aún no hay análisis guardados.");
}

static void on_refresh_clicked(GtkWidget *widget, gpointer user_data)
{
    (void)widget;
    refresh((DashboardUi *)user_data);
}

/* Se dispara cada vez que la pestaña vuelve a mostrarse */
static void on_mapped(GtkWidget *widget, gpointer user_data)
{
    (void)widget;
    refresh((DashboardUi *)user_data);
}

/* Respuesta del cuadro de confirmación: índice 1 = "Borrar" */
static void on_clear_finished(GObject *source, GAsyncResult *result, gpointer user_data)
{
    DashboardUi *ui = user_data;
    GError *error = NULL;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(source), result, &error);

    g_object_unref(source);

    if (error) {
        g_error_free(error);
        return;
    }
    if (choice != 1)
        return;

    if (db_clear_history(ui->db) == 0)
        gtk_label_set_text(GTK_LABEL(ui->status_label), "Historial borrado.");
    else
        gtk_label_set_text(GTK_LABEL(ui->status_label), "No se pudo borrar el historial.");

    refresh(ui);
}

static void on_clear_clicked(GtkWidget *widget, gpointer user_data)
{
    DashboardUi *ui = user_data;
    static const char *buttons[] = {"Cancelar", "Borrar", NULL};
    GtkAlertDialog *dialog = gtk_alert_dialog_new("¿Borrar todo el historial?");
    GtkRoot *root = gtk_widget_get_root(widget);
    GtkWindow *parent = GTK_IS_WINDOW(root) ? GTK_WINDOW(root) : NULL;

    gtk_alert_dialog_set_detail(dialog,
                                "Se eliminarán los análisis de URLs, correos y campañas guardados. "
                                "Esta acción no se puede deshacer.");
    gtk_alert_dialog_set_buttons(dialog, buttons);
    gtk_alert_dialog_set_cancel_button(dialog, 0);
    gtk_alert_dialog_set_default_button(dialog, 0);
    gtk_alert_dialog_choose(dialog, parent, NULL, on_clear_finished, ui);
}

GtkWidget *dashboard_new(Database *db)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *stats = gtk_label_new("");
    GtkWidget *summary = gtk_label_new("");
    GtkWidget *guide = gtk_label_new(
        "¿Cómo leer las gráficas? Cada anillo equivale al 100% de los análisis de ese tipo. "
        "Cada color es un nivel de riesgo: verde = bajo, naranja = sospechoso, rojo = alto. "
        "El número del centro es el total analizado.");
    GtkWidget *chart = gtk_drawing_area_new();
    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *refresh_button = gtk_button_new_with_label("Actualizar");
    GtkWidget *clear_button = gtk_button_new_with_label("Borrar historial");
    GtkWidget *status = gtk_label_new("");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    DashboardUi *ui = g_new0(DashboardUi, 1);

    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);

    gtk_label_set_xalign(GTK_LABEL(stats), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(summary), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(guide), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(guide), TRUE);
    gtk_widget_add_css_class(guide, "dim-label");
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);

    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(chart), 280);
    gtk_widget_set_hexpand(chart, TRUE);

    gtk_widget_set_hexpand(actions, FALSE);
    gtk_widget_add_css_class(clear_button, "destructive-action");
    gtk_box_append(GTK_BOX(actions), refresh_button);
    gtk_box_append(GTK_BOX(actions), clear_button);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 8);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(box), summary);
    gtk_box_append(GTK_BOX(box), guide);
    gtk_box_append(GTK_BOX(box), chart);
    gtk_box_append(GTK_BOX(box), stats);
    gtk_box_append(GTK_BOX(box), actions);
    gtk_box_append(GTK_BOX(box), status);
    gtk_box_append(GTK_BOX(box), scroll);

    ui->db = db;
    ui->stats_label = stats;
    ui->summary_label = summary;
    ui->chart = chart;
    ui->status_label = status;
    ui->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    ui_setup_tags(ui->buffer);

    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(chart), draw_chart, ui, NULL);

    g_signal_connect(refresh_button, "clicked", G_CALLBACK(on_refresh_clicked), ui);
    g_signal_connect(clear_button, "clicked", G_CALLBACK(on_clear_clicked), ui);
    g_signal_connect(box, "map", G_CALLBACK(on_mapped), ui);
    g_object_set_data_full(G_OBJECT(box), "dashboard-ui", ui, g_free);

    refresh(ui);
    return box;
}
