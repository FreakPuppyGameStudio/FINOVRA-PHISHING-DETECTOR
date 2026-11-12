#include "ui_common.h"
#include "ui_pages.h"

static void write_intro(GtkTextBuffer *buf)
{
    ui_append_title(buf, "Cómo se analiza\n\n");
    ui_append(buf,
              "Todo el análisis se hace en tu equipo. Ningún archivo se abre, ningún adjunto se "
              "ejecuta, ninguna URL se visita y no se consulta ningún servicio externo.\n\n");
}

static void write_urls(GtkTextBuffer *buf)
{
    ui_append_title(buf, "1. URLs\n");
    ui_append(buf, "Cada indicador se evalúa por separado y muestra su nivel:\n");
    ui_append(buf, "  • Credenciales en la URL (texto antes del @): ");
    ui_append_badge(buf, URL_RISK_HIGH);
    ui_append(buf, "\n");
    ui_append(buf, "  • Acortador de URL (bit.ly, tinyurl, etc.): ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, "\n");
    ui_append(buf, "  • IP en lugar de dominio: ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, ", alto si además usa un puerto no estándar\n");
    ui_append(buf, "  • Nombre parecido a una marca conocida (1 o 2 letras de diferencia), o marca "
                   "dentro de un subdominio: ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, ", alto con dominios de registro barato (.xyz, .top, .tk…)\n");
    ui_append(buf, "  • Caracteres codificados (%xx) o Unicode: ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, ", alto con punycode que imita una marca\n");
    ui_append(buf, "  • Guiones en el dominio: ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, ", sospechoso si además hay una marca\n");
    ui_append(buf, "  • Tres o más subdominios: ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, ", sospechoso si además hay una marca\n\n");
}

static void write_emails(GtkTextBuffer *buf)
{
    ui_append_title(buf, "2. Correos\n");
    ui_append(buf, "  • Remitente: Reply-To o Return-Path de otro dominio: ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, ". Una marca en el nombre visible sin su dominio oficial: ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, "\n");
    ui_append(buf, "  • Autenticación (leída de las cabeceras, no verificada criptográficamente): "
                   "DMARC fallido ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, "; SPF o DKIM fallidos ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, "; sin resultados ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, "\n");
    ui_append(buf, "  • Enlaces: el peor enlace pasa por el análisis de URLs de arriba\n");
    ui_append(buf, "  • Lenguaje de urgencia: una palabra ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, ", dos o más ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, "\n");
    ui_append(buf, "  • Petición de contraseña, tarjeta o datos bancarios: ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, ", sospechosa si hay enlaces, alta si el enlace es de alto riesgo\n");
    ui_append(buf, "  • Adjunto ejecutable (.exe, .js, .bat…): ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, ", alto con doble extensión (informe.pdf.exe)\n\n");
}

static void write_campaigns(GtkTextBuffer *buf)
{
    ui_append_title(buf, "3. Campañas\n");
    ui_append(buf, "Dos correos se relacionan si suman 3 puntos o más:\n");
    ui_append(buf, "  • Enlace idéntico: 3   • Mismo servidor de enlace: 2\n");
    ui_append(buf, "  • Misma dirección de remitente: 2   • Mismo dominio de remitente: 1\n");
    ui_append(buf, "  • Mismo asunto (sin Re: ni Fwd:): 2   • Asunto parecido: 1\n");
    ui_append(buf, "  • Texto parecido (la mitad o más de las palabras): 2\n");
    ui_append(buf, "  • Misma marca mencionada: 1\n");
    ui_append(buf, "Los pares relacionados se agrupan en campañas. Un asunto igual por sí solo no basta.\n\n");
}

static void write_final_level(GtkTextBuffer *buf)
{
    ui_append_title(buf, "4. Nivel final\n");
    ui_append(buf, "Todos los indicadores se combinan con esta regla:\n");
    ui_append(buf, "  ");
    ui_append_badge(buf, URL_RISK_HIGH);
    ui_append(buf, ": cualquier indicador alto, o dos o más sospechosos\n");
    ui_append(buf, "  ");
    ui_append_badge(buf, URL_RISK_SUSPICIOUS);
    ui_append(buf, ": un sospechoso, o dos o más débiles\n");
    ui_append(buf, "  ");
    ui_append_badge(buf, URL_RISK_LOW);
    ui_append(buf, ": el resto. Un solo indicador débil nunca marca algo como sospechoso.\n\n");
}

static void write_limits(GtkTextBuffer *buf)
{
    ui_append_title(buf, "Límites\n");
    ui_append_muted(buf,
                    "• Las palabras clave están en español e inglés y son pistas, no pruebas.\n"
                    "• SPF, DKIM y DMARC se leen de lo que dice el servidor; no se verifican firmas.\n"
                    "• La lista de marcas y de acortadores es corta y se puede ampliar.\n"
                    "• Los dominios con segundo nivel de país (google.co.uk) se tratan con una lista "
                    "fija, no con la lista pública de sufijos.\n"
                    "• Un resultado no es un veredicto: sirve para decidir qué revisar primero.\n");
}

GtkWidget *methodology_new(void)
{
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    GtkTextBuffer *buf;

    gtk_widget_set_margin_top(scroll, 12);
    gtk_widget_set_margin_bottom(scroll, 12);
    gtk_widget_set_margin_start(scroll, 12);
    gtk_widget_set_margin_end(scroll, 12);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 8);

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    ui_setup_tags(buf);
    ui_set_text(buf, "");

    write_intro(buf);
    write_urls(buf);
    write_emails(buf);
    write_campaigns(buf);
    write_final_level(buf);
    write_limits(buf);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    return scroll;
}
