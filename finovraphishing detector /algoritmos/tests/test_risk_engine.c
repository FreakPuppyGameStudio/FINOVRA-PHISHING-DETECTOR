#include <stdio.h>
#include <string.h>

#include "risk_engine.h"

static int failures = 0;

static UrlFinding make_finding(UrlRisk severity, const char *indicator, const char *reason)
{
    UrlFinding f;

    memset(&f, 0, sizeof f);
    snprintf(f.indicator, sizeof f.indicator, "%s", indicator);
    snprintf(f.reason, sizeof f.reason, "%s", reason);
    snprintf(f.evidence, sizeof f.evidence, "evidencia de prueba");
    f.severity = severity;
    f.confidence = URL_CONFIDENCE_MEDIUM;
    return f;
}

static void expect_level(const char *label, const UrlFinding *f, size_t n, UrlRisk expected)
{
    UrlRisk got = risk_aggregate(f, n);

    if (got != expected) {
        printf("FAIL: %-38s esperado '%s', obtenido '%s'\n",
               label, url_risk_name(expected), url_risk_name(got));
        failures++;
    } else {
        printf("ok:   %-38s -> %s\n", label, url_risk_name(got));
    }
}

static void expect_true(bool cond, const char *what)
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
    UrlFinding low = make_finding(URL_RISK_LOW, "debil", "Un indicador débil.");
    UrlFinding sus = make_finding(URL_RISK_SUSPICIOUS, "sospechoso", "Un indicador moderado.");
    UrlFinding high = make_finding(URL_RISK_HIGH, "alto", "Un indicador fuerte.");
    UrlFinding set[8];

    printf("--- Regla de agregación ---\n");
    expect_level("sin hallazgos", NULL, 0, URL_RISK_LOW);

    set[0] = low;
    expect_level("un débil", set, 1, URL_RISK_LOW);

    set[1] = low;
    expect_level("dos débiles", set, 2, URL_RISK_SUSPICIOUS);

    set[0] = sus;
    set[1] = low;
    expect_level("un sospechoso y un débil", set, 2, URL_RISK_SUSPICIOUS);

    set[0] = sus;
    expect_level("un sospechoso", set, 1, URL_RISK_SUSPICIOUS);

    set[0] = sus;
    set[1] = sus;
    expect_level("dos sospechosos", set, 2, URL_RISK_HIGH);

    set[2] = sus;
    expect_level("tres sospechosos", set, 3, URL_RISK_HIGH);

    set[0] = high;
    expect_level("un alto", set, 1, URL_RISK_HIGH);

    printf("\n--- Conteos ---\n");
    {
        UrlFinding mix[4];
        RiskCounts c;

        mix[0] = high;
        mix[1] = sus;
        mix[2] = low;
        mix[3] = low;
        risk_count(mix, 4, &c);
        expect_true(c.high == 1 && c.suspicious == 1 && c.low == 2, "conteo por severidad correcto");
    }

    printf("\n--- Explicación ---\n");
    {
        char text[512];
        UrlFinding mix[2];

        mix[0] = low;
        mix[1] = sus;
        expect_true(risk_explain(mix, 2, text, sizeof text) == 0, "risk_explain devuelve 0");
        expect_true(strstr(text, "Nivel final: Sospechosa") != NULL, "resumen indica el nivel final");
        expect_true(strstr(text, "Motivo principal: Un indicador moderado.") != NULL,
                    "resumen cita el hallazgo más fuerte");
        expect_true(risk_explain(mix, 2, NULL, 0) != 0, "buffer nulo se rechaza");

        expect_true(risk_explain(NULL, 0, text, sizeof text) == 0, "sin hallazgos también explica");
        expect_true(strstr(text, "No se encontraron indicadores") != NULL,
                    "sin hallazgos el texto lo dice");
    }

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
