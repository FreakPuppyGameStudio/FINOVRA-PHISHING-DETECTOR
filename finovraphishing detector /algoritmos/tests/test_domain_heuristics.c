#include <stdio.h>
#include <string.h>

#include "url_analyzer.h"

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

static bool has_indicator(const UrlReport *r, const char *name)
{
    for (size_t i = 0; i < r->finding_count; i++) {
        if (strcmp(r->findings[i].indicator, name) == 0)
            return true;
    }
    return false;
}

static size_t count_findings(const UrlReport *r)
{
    return r->finding_count;
}

int main(void)
{
    UrlReport r;

    printf("--- Nombres con apariencia aleatoria ---\n");
    check(url_analyze("https://xk7q9vbz2mrt.com/", &r) == 0, "dominio aleatorio se analiza");
    check(has_indicator(&r, "nombre_aleatorio_con_digitos"), "nombre aleatorio con dígitos se marca");
    check(r.overall != URL_RISK_LOW, "un nombre aleatorio con dígitos no queda en bajo riesgo");

    printf("\n--- Combinaciones de características ---\n");
    check(url_analyze("https://secure-account-verify-login.xyz/", &r) == 0, "dominio de acceso se analiza");
    check(has_indicator(&r, "palabra_de_acceso"), "palabra de acceso en el nombre se marca");
    check(has_indicator(&r, "tld_de_registro_barato"), "extensión barata se marca");
    check(has_indicator(&r, "nombre_muy_largo"), "nombre muy largo se marca");
    check(r.overall == URL_RISK_SUSPICIOUS, "dos características débiles dan sospechosa");

    printf("\n--- Sin falsos positivos en dominios normales ---\n");
    check(url_analyze("https://www.wikipedia.org/wiki/Phishing", &r) == 0, "wikipedia se analiza");
    check(count_findings(&r) == 0 && r.overall == URL_RISK_LOW,
          "wikipedia no recibe ninguna característica");

    check(url_analyze("https://mercadolibre.com.mx/", &r) == 0, "mercadolibre se analiza");
    check(!has_indicator(&r, "nombre_aleatorio") && !has_indicator(&r, "nombre_aleatorio_con_digitos"),
          "marca conocida no se considera aleatoria");

    check(url_analyze("https://www.google.co.uk/", &r) == 0, "google.co.uk se analiza");
    check(r.overall == URL_RISK_LOW, "google.co.uk sigue en bajo riesgo");

    check(url_analyze("https://a.b.c.d.example.com/", &r) == 0, "subdominios profundos se analizan");
    check(!has_indicator(&r, "palabra_de_acceso"), "palabras en subdominios no cuentan (solo el nombre principal)");

    check(url_analyze("http://192.168.1.10/login", &r) == 0, "IP se analiza");
    check(!has_indicator(&r, "nombre_aleatorio"), "las IP no reciben características de nombre");

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
