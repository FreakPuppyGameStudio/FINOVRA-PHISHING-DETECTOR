#include <stdio.h>

#include "intel.h"
#include "risk_engine.h"
#include "ui_common.h"
#include "ui_pages.h"
#include "url_analyzer.h"

typedef struct {
    GtkWidget *entry;
    GtkTextBuffer *buffer;
    Database *db;
    Blocklist *blocklist;
    gchar *blocklist_path;
} UrlScannerUi;

/* Carga la lista local desde ~/.local/share/finovra-phishing/blocklist.txt, si existe */
static void load_blocklist(UrlScannerUi *ui)
{
    gchar *dir = g_build_filename(g_get_user_data_dir(), "finovra-phishing", NULL);

    ui->blocklist = intel_blocklist_new();
    ui->blocklist_path = g_build_filename(dir, "blocklist.txt", NULL);
    if (ui->blocklist)
        intel_blocklist_load_file(ui->blocklist, ui->blocklist_path, NULL);
    g_free(dir);
}

static void render_report(UrlScannerUi *ui, const UrlReport *report)
{
    GtkTextBuffer *buf = ui->buffer;
    char line[2 * URL_TEXT_LEN + 128];

    ui_set_text(buf, "");
    ui_append_title(buf, "Resultado: ");
    ui_append_badge(buf, report->overall);
    ui_append(buf, "\n\n");

    if (report->finding_count == 0)
        ui_append_muted(buf, "No se encontraron indicadores sospechosos.\n\n");

    for (size_t i = 0; i < report->finding_count; i++) {
        const UrlFinding *f = &report->findings[i];

        ui_append_badge(buf, f->severity);
        snprintf(line, sizeof line, "  %s\n", f->indicator);
        ui_append(buf, line);
        snprintf(line, sizeof line, "  Razón: %s\n", f->reason);
        ui_append(buf, line);
        snprintf(line, sizeof line, "  Evidencia: %s\n\n", f->evidence);
        ui_append_muted(buf, line);
    }

    if (ui->blocklist && intel_blocklist_size(ui->blocklist) > 0) {
        snprintf(line, sizeof line,
                 "Lista local de dominios maliciosos: %zu dominios cargados.\n",
                 intel_blocklist_size(ui->blocklist));
        ui_append_muted(buf, line);
    } else {
        snprintf(line, sizeof line,
                 "Lista local de dominios maliciosos: no configurada. Para usarla, crea el archivo\n%s\n"
                 "con un dominio por línea.\n",
                 ui->blocklist_path ? ui->blocklist_path : "(ruta no disponible)");
        ui_append_muted(buf, line);
    }

    ui_append_muted(buf, "Análisis local: la URL no se abrió ni se consultó ningún servicio externo.\n");
}

static void on_scan_requested(GtkWidget *widget, gpointer user_data)
{
    UrlScannerUi *ui = user_data;
    const char *text = gtk_editable_get_text(GTK_EDITABLE(ui->entry));
    UrlReport report;
    char summary[1024];

    (void)widget;

    if (url_analyze(text, &report) != 0) {
        ui_set_text(ui->buffer,
                    "No se pudo analizar. Escribe una URL completa, por ejemplo https://ejemplo.com");
        return;
    }

    intel_apply_blocklist(ui->blocklist, text, &report);
    render_report(ui, &report);

    if (risk_explain(report.findings, report.finding_count, summary, sizeof summary) == 0 &&
        db_save_url_scan(ui->db, text, report.overall, summary, NULL) == 0) {
        ui_append_muted(ui->buffer, "\nGuardado en el historial.\n");
    } else {
        ui_append_muted(ui->buffer, "\nNo se pudo guardar en el historial.\n");
    }
}

static void free_url_ui(gpointer data)
{
    UrlScannerUi *ui = data;

    intel_blocklist_free(ui->blocklist);
    g_free(ui->blocklist_path);
    g_free(ui);
}

GtkWidget *url_scanner_new(Database *db)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *button = gtk_button_new_with_label("Analizar");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    UrlScannerUi *ui = g_new0(UrlScannerUi, 1);

    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);

    ui->entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ui->entry), "https://ejemplo.com/ruta");
    gtk_widget_set_hexpand(ui->entry, TRUE);

    gtk_box_append(GTK_BOX(row), ui->entry);
    gtk_box_append(GTK_BOX(row), button);
    gtk_box_append(GTK_BOX(box), row);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 8);
    ui->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    ui_setup_tags(ui->buffer);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(box), scroll);

    ui->db = db;
    load_blocklist(ui);

    g_signal_connect(button, "clicked", G_CALLBACK(on_scan_requested), ui);
    g_signal_connect(ui->entry, "activate", G_CALLBACK(on_scan_requested), ui);
    g_object_set_data_full(G_OBJECT(box), "url-scanner-ui", ui, free_url_ui);

    ui_set_text(ui->buffer,
                "Pega una URL y pulsa Analizar. El análisis es local: la URL no se abre.");
    return box;
}
