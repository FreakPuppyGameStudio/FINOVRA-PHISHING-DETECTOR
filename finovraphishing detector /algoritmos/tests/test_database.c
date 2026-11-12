#include <stdio.h>
#include <string.h>

#include "database.h"

static int failures = 0;

static void check(bool cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok:   %s\n", what);
    }
}

static const char *EMAIL_A =
    "From: PayPal Soporte <soporte@paypal-seguridad.xyz>\n"
    "Reply-To: respuesta@correo-rapido.top\n"
    "Subject: Acción requerida\n"
    "Message-ID: <a1@paypal-seguridad.xyz>\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Verifica en https://paypal-seguridad.xyz/verificar y en https://paypal-seguridad.xyz/ayuda\n";

static const char *EMAIL_B =
    "From: Cuenta <otro@correo-rapido.top>\n"
    "Subject: Re: Acción requerida\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Revisa https://paypal-seguridad.xyz/verificar gracias\n";

int main(void)
{
    Database *db = NULL;
    EmailMessage ma;
    EmailMessage mb;
    DbStats s;
    int64_t id = 0;
    int64_t ids[2];

    printf("--- Apertura ---\n");
    check(db_open(NULL, &db) != 0, "ruta nula se rechaza");
    check(db_open(":memory:", &db) == 0 && db != NULL, "base en memoria se abre");
    check(db_stats(db, &s) == 0, "estadísticas en base vacía");
    check(s.url_scans == 0 && s.emails == 0 && s.campaigns == 0 && s.high_risk == 0,
          "base vacía: todos los conteos en cero");

    printf("\n--- URLs ---\n");
    check(db_save_url_scan(db, "https://paypa1.com/login", URL_RISK_SUSPICIOUS,
                           "Sospechosa: dominio parecido", &id) == 0, "guarda URL sospechosa");
    check(id > 0, "devuelve el id guardado");
    check(db_save_url_scan(db, "http://192.168.1.10:8080/", URL_RISK_HIGH,
                           "Alto riesgo: IP con puerto", NULL) == 0, "guarda URL de alto riesgo");
    check(db_save_url_scan(db, NULL, URL_RISK_LOW, "x", NULL) != 0, "URL nula se rechaza");
    check(db_stats(db, &s) == 0 && s.url_scans == 2 && s.high_risk == 1,
          "estadísticas: 2 URLs, 1 de alto riesgo");

    printf("\n--- Correos ---\n");
    check(email_parse(EMAIL_A, strlen(EMAIL_A), &ma) == 0, "correo A se parsea");
    check(email_parse(EMAIL_B, strlen(EMAIL_B), &mb) == 0, "correo B se parsea");

    check(db_save_email(db, &ma, URL_RISK_HIGH, "Alto riesgo: phishing evidente", &ids[0]) == 0,
          "guarda correo A con su riesgo");
    check(ids[0] > 0, "devuelve el id del correo A");
    check(db_save_email(db, &mb, URL_RISK_SUSPICIOUS, "Sospechosa", &ids[1]) == 0,
          "guarda correo B");
    check(db_save_email(db, &ma, URL_RISK_LOW, NULL, NULL) != 0, "resumen nulo se rechaza");

    check(db_stats(db, &s) == 0 && s.emails == 2, "estadísticas: 2 correos");
    check(s.email_urls == 3, "estadísticas: 3 enlaces guardados (2 de A, 1 de B)");
    check(s.high_risk == 2, "alto riesgo: 1 URL + 1 correo");

    printf("\n--- Campañas ---\n");
    {
        Campaign c;

        memset(&c, 0, sizeof c);
        c.members[0] = 0;
        c.members[1] = 1;
        c.member_count = 2;
        c.signals = CAMPAIGN_SIG_SHARED_URL | CAMPAIGN_SIG_SUBJECT_EQUAL;
        snprintf(c.summary, sizeof c.summary, "Campaña de 2 correos. Comparten: enlace idéntico.");

        check(db_save_campaign(db, &c, ids, 2, &id) == 0, "guarda campaña con dos correos");
        check(db_stats(db, &s) == 0 && s.campaigns == 1, "estadísticas: 1 campaña");

        {
            Campaign bad = c;
            int64_t fake_ids[2] = {ids[0], 999999};

            check(db_save_campaign(db, &bad, fake_ids, 2, NULL) != 0,
                  "id de correo inexistente se rechaza por llave foránea");
            check(db_stats(db, &s) == 0 && s.campaigns == 1,
                  "tras el error no queda campaña a medias (rollback)");
        }
        {
            Campaign out_of_range = c;

            out_of_range.members[1] = 5;
            check(db_save_campaign(db, &out_of_range, ids, 2, NULL) != 0,
                  "índice fuera de rango se rechaza");
        }
    }

    printf("\n--- Desglose por nivel ---\n");
    {
        DbRiskBreakdown b;

        check(db_risk_breakdown(db, &b) == 0, "desglose se calcula");
        check(b.url_suspicious == 1 && b.url_high == 1 && b.url_low == 0,
              "URLs: 1 sospechosa, 1 alta, 0 bajas");
        check(b.email_high == 1 && b.email_suspicious == 1 && b.email_low == 0,
              "correos: 1 alto, 1 sospechoso, 0 bajos");
    }

    printf("\n--- Historial reciente ---\n");
    {
        char recent[2048];

        check(db_recent_text(db, 5, recent, sizeof recent) == 0, "historial se genera");
        check(strstr(recent, "https://paypa1.com/login") != NULL, "historial incluye la URL guardada");
        check(strstr(recent, "[Correo]") != NULL, "historial incluye los correos");
    }

    printf("\n--- Borrado del historial ---\n");
    check(db_clear_history(db) == 0, "historial se borra");
    check(db_stats(db, &s) == 0 && s.url_scans == 0 && s.emails == 0 &&
          s.email_urls == 0 && s.campaigns == 0 && s.high_risk == 0,
          "tras borrar, todos los conteos quedan en cero");
    check(db_clear_history(db) == 0, "borrar un historial ya vacío no falla");

    email_free(&ma);
    email_free(&mb);
    db_close(db);

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
