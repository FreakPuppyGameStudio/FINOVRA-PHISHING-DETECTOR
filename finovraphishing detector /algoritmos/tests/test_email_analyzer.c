#include <stdio.h>
#include <string.h>

#include "email_analyzer.h"

static int failures = 0;

static const char *CLEAN_EMAIL =
    "From: Ventas <ventas@empresa.com>\n"
    "Reply-To: ventas@empresa.com\n"
    "Subject: Propuesta de\n"
    " junio\n"
    "Date: Mon, 10 Nov 2026 19:00:00 -0600\n"
    "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=empresa.com; "
    "dkim=pass header.d=empresa.com; dmarc=pass\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "Content-Transfer-Encoding: quoted-printable\n"
    "\n"
    "Hola, te comparto la propuesta. Precio: 5=C3=A1 pesos.\n"
    "Saludos.\n";

static const char *PHISHING_EMAIL =
    "From: PayPal Soporte <soporte@paypal-seguridad.xyz>\n"
    "Reply-To: respuesta@correo-rapido.top\n"
    "Subject: Acción requerida\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "URGENTE: tu cuenta sera suspendida. Ingresa tu contrasena en "
    "https://paypal-seguridad.xyz/verificar para evitarlo.\n";

static const char *DOUBLE_EXT_EMAIL =
    "From: Finanzas <finanzas@empresa.com>\n"
    "Subject: Factura\n"
    "Content-Type: multipart/mixed; boundary=\"XYZ\"\n"
    "\n"
    "--XYZ\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Adjunto el informe.\n"
    "--XYZ\n"
    "Content-Type: application/octet-stream; name=\"informe.pdf.exe\"\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Disposition: attachment; filename=\"informe.pdf.exe\"\n"
    "\n"
    "TVqQAAMAAAAEAAAA\n"
    "--XYZ--\n";

static const char *SINGLE_EXE_EMAIL =
    "From: Soporte <soporte@empresa.com>\n"
    "Subject: Programa\n"
    "Content-Type: multipart/mixed; boundary=\"B1\"\n"
    "\n"
    "--B1\n"
    "Content-Type: text/plain\n"
    "\n"
    "Te envío el instalador.\n"
    "--B1\n"
    "Content-Type: application/octet-stream\n"
    "Content-Disposition: attachment; filename=instalar.exe\n"
    "\n"
    "TVqQAAMAAAAEAAAA\n"
    "--B1--\n";

static void expect_overall(const char *label, const char *raw, UrlRisk expected)
{
    EmailMessage m;
    EmailReport r;

    if (email_parse(raw, strlen(raw), &m) != 0 || email_analyze(&m, &r) != 0) {
        printf("FAIL: '%s' no se pudo procesar\n", label);
        failures++;
        email_free(&m);
        return;
    }

    if (r.overall != expected) {
        printf("FAIL: '%s' esperado '%s', obtenido '%s'\n",
               label, url_risk_name(expected), url_risk_name(r.overall));
        failures++;
    } else {
        printf("ok:   %-34s -> %s\n", label, url_risk_name(r.overall));
    }
    email_free(&m);
}

static void expect_indicator(const char *label, const char *raw, const char *indicator)
{
    EmailMessage m;
    EmailReport r;
    bool found = false;

    if (email_parse(raw, strlen(raw), &m) != 0 || email_analyze(&m, &r) != 0) {
        printf("FAIL: '%s' no se pudo procesar\n", label);
        failures++;
        email_free(&m);
        return;
    }
    for (size_t i = 0; i < r.finding_count; i++) {
        if (strcmp(r.findings[i].indicator, indicator) == 0)
            found = true;
    }
    if (!found) {
        printf("FAIL: '%s' no reporta '%s'\n", label, indicator);
        failures++;
    } else {
        printf("ok:   %-34s incluye %s\n", label, indicator);
    }
    email_free(&m);
}

static void check(bool cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok:   %s\n", what);
    }
}

int main(void)
{
    EmailMessage m;

    printf("--- Parseo ---\n");
    check(email_parse(NULL, 0, &m) != 0, "NULL se rechaza");

    if (email_parse(CLEAN_EMAIL, strlen(CLEAN_EMAIL), &m) == 0) {
        check(strcmp(m.subject, "Propuesta de junio") == 0, "cabecera plegada: asunto unido");
        check(strcmp(m.from, "Ventas <ventas@empresa.com>") == 0, "remitente leído");
        check(m.has_auth_results, "Authentication-Results detectada");
        check(strstr(m.body, "5á pesos") != NULL, "quoted-printable decodificado (=C3=A1 -> á)");
        check(m.attachment_count == 0, "sin adjuntos en correo de texto");
        email_free(&m);
    } else {
        check(false, "correo limpio se parsea");
    }

    if (email_parse(DOUBLE_EXT_EMAIL, strlen(DOUBLE_EXT_EMAIL), &m) == 0) {
        check(m.attachment_count == 1, "multipart: un adjunto encontrado");
        check(m.attachment_count == 1 &&
              strcmp(m.attachments[0].name, "informe.pdf.exe") == 0,
              "adjunto: nombre leído desde filename");
        check(strstr(m.body, "Adjunto el informe") != NULL, "multipart: parte de texto leída");
        email_free(&m);
    } else {
        check(false, "correo multipart se parsea");
    }

    printf("\n--- Niveles de riesgo ---\n");
    expect_overall("correo limpio", CLEAN_EMAIL, URL_RISK_LOW);
    expect_overall("phishing evidente", PHISHING_EMAIL, URL_RISK_HIGH);
    expect_overall("adjunto con doble extensión", DOUBLE_EXT_EMAIL, URL_RISK_HIGH);
    expect_overall("adjunto .exe simple", SINGLE_EXE_EMAIL, URL_RISK_SUSPICIOUS);

    printf("\n--- Indicadores esperados ---\n");
    expect_indicator("phishing", PHISHING_EMAIL, "marca_en_nombre_remitente");
    expect_indicator("phishing", PHISHING_EMAIL, "dmarc_fallido");
    expect_indicator("phishing", PHISHING_EMAIL, "lenguaje_urgente");
    expect_indicator("phishing", PHISHING_EMAIL, "solicita_credenciales");
    expect_indicator("phishing", PHISHING_EMAIL, "enlace_sospechoso");
    expect_indicator("phishing", PHISHING_EMAIL, "reply_to_distinto");
    expect_indicator("doble extensión", DOUBLE_EXT_EMAIL, "adjunto_doble_extension");

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
