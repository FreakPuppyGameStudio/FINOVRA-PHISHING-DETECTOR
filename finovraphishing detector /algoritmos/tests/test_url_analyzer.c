#include <stdio.h>
#include <string.h>

#include "url_analyzer.h"

static int failures = 0;

static void expect_risk(const char *url, UrlRisk expected)
{
    UrlReport r;

    if (url_analyze(url, &r) != 0) {
        printf("FAIL: '%s' no se pudo analizar\n", url);
        failures++;
        return;
    }

    if (r.overall != expected) {
        printf("FAIL: '%s' esperado '%s', obtenido '%s'\n",
               url, url_risk_name(expected), url_risk_name(r.overall));
        failures++;
    } else {
        printf("ok:   %-42s -> %s\n", url, url_risk_name(r.overall));
    }
}

static void expect_indicator(const char *url, const char *indicator)
{
    UrlReport r;
    bool found = false;

    if (url_analyze(url, &r) != 0) {
        printf("FAIL: '%s' no se pudo analizar\n", url);
        failures++;
        return;
    }

    for (size_t i = 0; i < r.finding_count; i++) {
        if (strcmp(r.findings[i].indicator, indicator) == 0)
            found = true;
    }

    if (!found) {
        printf("FAIL: '%s' no reporta el indicador '%s'\n", url, indicator);
        failures++;
    } else {
        printf("ok:   %-42s incluye %s\n", url, indicator);
    }
}

static void expect_parse_error(const char *url)
{
    UrlReport r;

    if (url_analyze(url, &r) == 0) {
        printf("FAIL: '%s' debería ser inválida\n", url);
        failures++;
    } else {
        printf("ok:   %-42s rechazada\n", url);
    }
}

static void expect_int(int actual, int expected, const char *what)
{
    if (actual != expected) {
        printf("FAIL: %s: esperado %d, obtenido %d\n", what, expected, actual);
        failures++;
    } else {
        printf("ok:   %s = %d\n", what, actual);
    }
}

int main(void)
{
    printf("--- Niveles de riesgo ---\n");

    /* Sitios legítimos: no deben generar alarmas */
    expect_risk("https://www.google.com/search", URL_RISK_LOW);
    expect_risk("https://paypal.com/", URL_RISK_LOW);
    expect_risk("https://www.google.co.uk/", URL_RISK_LOW);
    expect_risk("https://amazonas.com.mx/", URL_RISK_LOW);
    expect_risk("https://a.b.c.d.example.com/", URL_RISK_LOW);      /* un solo indicador débil */
    expect_risk("https://secure-login-update.example.com/", URL_RISK_LOW);

    /* Indicadores aislados */
    expect_risk("http://192.168.1.10/login", URL_RISK_SUSPICIOUS);
    expect_risk("https://bit.ly/abc", URL_RISK_SUSPICIOUS);
    expect_risk("https://example.com/%20%41", URL_RISK_SUSPICIOUS);
    expect_risk("https://paypa1.com/login", URL_RISK_SUSPICIOUS);
    expect_risk("https://google-store.com/", URL_RISK_SUSPICIOUS); /* guion + marca */

    /* Dos indicadores débiles */
    expect_risk("https://a.b.c.my-site.com/", URL_RISK_SUSPICIOUS);

    /* Indicadores fuertes o combinaciones */
    expect_risk("http://192.168.1.10:8080/login", URL_RISK_HIGH);
    expect_risk("https://banco.com@sitio.xyz/login", URL_RISK_HIGH);
    expect_risk("https://paypal.com.secure.evil.xyz/", URL_RISK_HIGH);
    expect_risk("https://xn--pypal-4ve.com/", URL_RISK_HIGH);

    printf("\n--- Indicadores esperados ---\n");
    expect_indicator("https://paypa1.com/login", "marca_suplantada");
    expect_indicator("https://a.b.c.d.example.com/", "subdominios_excesivos");
    expect_indicator("https://secure-login-update.example.com/", "guiones_en_dominio");
    expect_indicator("https://bit.ly/abc", "acortador_url");
    expect_indicator("http://192.168.1.10/login", "ip_en_lugar_de_dominio");

    printf("\n--- Entradas inválidas ---\n");
    expect_parse_error("https://");
    expect_parse_error("   ");
    expect_parse_error("https://host:abc/");

    printf("\n--- Distancia de Levenshtein ---\n");
    expect_int(url_levenshtein("paypa1", "paypal"), 1, "levenshtein(paypa1, paypal)");
    expect_int(url_levenshtein("kitten", "sitting"), 3, "levenshtein(kitten, sitting)");
    expect_int(url_levenshtein("", "abc"), 3, "levenshtein(vacía, abc)");

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
