#include <stdio.h>
#include <stdlib.h>

#include "campaign_detector.h"
#include "email_analyzer.h"
#include "risk_engine.h"
#include "ui_common.h"
#include "ui_pages.h"

#define MAX_EML_SIZE (5 * 1024 * 1024)

typedef struct {
    GtkWidget *entry;
    GtkTextBuffer *buffer;
    Database *db;
    EmailMessage *session;                      /* correos guardados en esta sesión */
    int64_t session_ids[CAMPAIGN_MAX_EMAILS];   /* id en la base de cada correo de la sesión */
    size_t session_count;
} EmailViewerUi;

static void render_email(GtkTextBuffer *buf, const EmailMessage *m, const EmailReport *r)
{
    char line[4096];

    ui_set_text(buf, "");
    ui_append_title(buf, "Resultado: ");
    ui_append_badge(buf, r->overall);
    ui_append(buf, "\n\n");

    snprintf(line, sizeof line, "De: %s\n", m->from);
    ui_append(buf, line);
    snprintf(line, sizeof line, "Responder a: %s\n", m->reply_to[0] ? m->reply_to : "(no indicado)");
    ui_append(buf, line);
    snprintf(line, sizeof line, "Asunto: %s\n", m->subject);
    ui_append(buf, line);
    snprintf(line, sizeof line, "Fecha: %s\n", m->date[0] ? m->date : "(no indicada)");
    ui_append(buf, line);
    snprintf(line, sizeof line, "Enlaces encontrados: %zu\n", m->url_count);
    ui_append(buf, line);
    snprintf(line, sizeof line, "Adjuntos: %zu\n", m->attachment_count);
    ui_append(buf, line);

    for (size_t i = 0; i < m->attachment_count; i++) {
        const EmailAttachment *a = &m->attachments[i];

        snprintf(line, sizeof line, "  - %s (%s, %zu bytes; no se abrió)\n",
                 a->name, a->content_type, a->size);
        ui_append_muted(buf, line);
    }

    ui_append(buf, "\n");
    ui_append_title(buf, "Hallazgos\n");
    if (r->finding_count == 0)
        ui_append_muted(buf, "  Ninguno.\n");

    for (size_t i = 0; i < r->finding_count; i++) {
        const UrlFinding *f = &r->findings[i];

        ui_append_badge(buf, f->severity);
        snprintf(line, sizeof line, "  %s\n", f->indicator);
        ui_append(buf, line);
        snprintf(line, sizeof line, "  Razón: %s\n", f->reason);
        ui_append(buf, line);
        snprintf(line, sizeof line, "  Evidencia: %s\n\n", f->evidence);
        ui_append_muted(buf, line);
    }

    ui_append_muted(buf,
                    "Análisis local: el correo no se abrió, los adjuntos no se ejecutaron y los enlaces "
                    "no se visitaron. SPF, DKIM y DMARC se leen de las cabeceras; no se verifican "
                    "criptográficamente.\n");
}

static void render_campaigns(GtkTextBuffer *buf, const EmailViewerUi *ui, const CampaignReport *report)
{
    char line[2048];

    ui_set_text(buf, "");

    if (report->campaign_count == 0) {
        ui_append_muted(buf, "No se encontraron campañas entre los correos de esta sesión.\n");
        return;
    }

    for (size_t c = 0; c < report->campaign_count; c++) {
        const Campaign *camp = &report->campaigns[c];

        ui_append_title(buf, "Campaña ");
        snprintf(line, sizeof line, "%zu\n%s\n", c + 1, camp->summary);
        ui_append(buf, line);

        for (size_t m = 0; m < camp->member_count; m++) {
            const EmailMessage *msg = &ui->session[camp->members[m]];

            snprintf(line, sizeof line, "  - De: %s | Asunto: %s\n", msg->from, msg->subject);
            ui_append(buf, line);
        }
        ui_append(buf, "\n");
    }

    ui_append_muted(buf,
                    "Las campañas se calculan con señales simples (enlaces, remitente, asunto y texto). "
                    "Revísalas antes de concluir algo.\n");
}

/* ------------------------------------------------------------------ */
/* Acciones                                                            */
/* ------------------------------------------------------------------ */

static void on_analyze_requested(GtkWidget *widget, gpointer user_data)
{
    EmailViewerUi *ui = user_data;
    const char *path = gtk_editable_get_text(GTK_EDITABLE(ui->entry));
    gchar *contents = NULL;
    gsize length = 0;
    GError *error = NULL;
    EmailMessage temp;
    EmailMessage *msg;
    bool stored;
    bool saved = false;
    EmailReport report;
    char summary[1024];
    int64_t id = 0;

    (void)widget;

    if (path[0] == '\0') {
        ui_set_text(ui->buffer, "Escribe la ruta completa de un archivo .eml.");
        return;
    }

    if (!g_file_get_contents(path, &contents, &length, &error)) {
        char msg_text[1024];

        snprintf(msg_text, sizeof msg_text, "No se pudo leer el archivo: %s",
                 error ? error->message : "error desconocido");
        ui_set_text(ui->buffer, msg_text);
        if (error)
            g_error_free(error);
        return;
    }

    if (length > MAX_EML_SIZE) {
        ui_set_text(ui->buffer, "El archivo es demasiado grande para analizarlo (máximo 5 MB).");
        g_free(contents);
        return;
    }

    /* Si la sesión tiene espacio, el correo se analiza directamente en su lugar de la sesión */
    stored = ui->session_count < CAMPAIGN_MAX_EMAILS;
    msg = stored ? &ui->session[ui->session_count] : &temp;

    if (email_parse(contents, (size_t)length, msg) != 0) {
        ui_set_text(ui->buffer, "No se pudo interpretar el archivo como correo.");
        g_free(contents);
        return;
    }

    if (email_analyze(msg, &report) != 0) {
        ui_set_text(ui->buffer, "Ocurrió un error durante el análisis.");
        email_free(msg);
        g_free(contents);
        return;
    }

    render_email(ui->buffer, msg, &report);

    if (risk_explain(report.findings, report.finding_count, summary, sizeof summary) == 0 &&
        db_save_email(ui->db, msg, report.overall, summary, &id) == 0) {
        saved = true;
        ui_append_muted(ui->buffer, "\nGuardado en el historial.\n");
    } else {
        ui_append_muted(ui->buffer, "\nNo se pudo guardar en el historial.\n");
    }

    /* Solo se conserva en la sesión si quedó guardado: así los ids siempre coinciden */
    if (stored && saved) {
        ui->session_ids[ui->session_count] = id;
        ui->session_count++;
    } else {
        email_free(msg);
    }

    g_free(contents);
}

static void on_campaigns_requested(GtkWidget *widget, gpointer user_data)
{
    EmailViewerUi *ui = user_data;
    static CampaignReport report;
    size_t failed = 0;
    char line[128];

    (void)widget;

    if (ui->session_count < 2) {
        ui_set_text(ui->buffer,
                    "Analiza al menos dos correos en esta sesión para buscar campañas.");
        return;
    }

    if (campaign_detect(ui->session, ui->session_count, &report) != 0) {
        ui_set_text(ui->buffer, "No se pudo calcular las campañas.");
        return;
    }

    for (size_t c = 0; c < report.campaign_count; c++) {
        if (db_save_campaign(ui->db, &report.campaigns[c], ui->session_ids,
                             ui->session_count, NULL) != 0)
            failed++;
    }

    render_campaigns(ui->buffer, ui, &report);

    snprintf(line, sizeof line, "\nCampañas guardadas: %zu de %zu.\n",
             report.campaign_count - failed, report.campaign_count);
    ui_append_muted(ui->buffer, line);
}

/* Libera la sesión cuando se destruye la página */
static void free_email_ui(gpointer data)
{
    EmailViewerUi *ui = data;

    for (size_t i = 0; i < ui->session_count; i++)
        email_free(&ui->session[i]);
    free(ui->session);
    g_free(ui);
}

/* ------------------------------------------------------------------ */
/* Construcción                                                        */
/* ------------------------------------------------------------------ */

GtkWidget *email_viewer_new(Database *db)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *analyze_button = gtk_button_new_with_label("Analizar .eml");
    GtkWidget *campaign_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *campaign_button = gtk_button_new_with_label("Buscar campañas");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    EmailViewerUi *ui = g_new0(EmailViewerUi, 1);

    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);

    ui->entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ui->entry), "/home/usuario/correo.eml");
    gtk_widget_set_hexpand(ui->entry, TRUE);

    gtk_box_append(GTK_BOX(row), ui->entry);
    gtk_box_append(GTK_BOX(row), analyze_button);
    gtk_box_append(GTK_BOX(box), row);

    gtk_widget_set_halign(campaign_button, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(campaign_row), campaign_button);
    gtk_box_append(GTK_BOX(box), campaign_row);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    ui->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    ui_setup_tags(ui->buffer);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(box), scroll);

    ui->db = db;
    ui->session = calloc(CAMPAIGN_MAX_EMAILS, sizeof *ui->session);
    ui->session_count = 0;

    g_signal_connect(analyze_button, "clicked", G_CALLBACK(on_analyze_requested), ui);
    g_signal_connect(ui->entry, "activate", G_CALLBACK(on_analyze_requested), ui);
    g_signal_connect(campaign_button, "clicked", G_CALLBACK(on_campaigns_requested), ui);
    g_object_set_data_full(G_OBJECT(box), "email-viewer-ui", ui, free_email_ui);

    ui_set_text(ui->buffer,
                "Escribe la ruta completa de un archivo .eml y pulsa Analizar. "
                "Cada correo analizado se guarda en el historial y forma parte de la sesión. "
                "Con dos o más correos puedes buscar campañas.");
    return box;
}
