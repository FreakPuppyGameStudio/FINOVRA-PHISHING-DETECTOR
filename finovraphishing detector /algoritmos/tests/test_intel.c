#include <stdio.h>
#include <string.h>

#include "intel.h"

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

#define TEST_FILE "intel_test_blocklist.txt"

int main(void)
{
    Blocklist *bl = intel_blocklist_new();
    UrlReport report;
    size_t loaded = 0;
    FILE *f;

    printf("--- Alta manual ---\n");
    check(bl != NULL, "lista se crea");
    check(intel_blocklist_add(bl, "Evil.COM") == 0, "dominio con mayúsculas se acepta");
    check(intel_blocklist_add(bl, "   ") != 0, "línea vacía se rechaza");
    check(intel_blocklist_add(bl, "https://malo.net/x") != 0, "URL completa se rechaza");
    check(intel_blocklist_size(bl) == 1, "solo se guardó un dominio válido");

    printf("\n--- Coincidencia de hosts ---\n");
    check(intel_blocklist_contains_host(bl, "evil.com"), "coincide el dominio exacto");
    check(intel_blocklist_contains_host(bl, "www.evil.com"), "coincide un subdominio");
    check(intel_blocklist_contains_host(bl, "a.b.evil.com"), "coincide un subdominio profundo");
    check(!intel_blocklist_contains_host(bl, "notevil.com"), "no coincide un dominio que solo termina igual");
    check(!intel_blocklist_contains_host(bl, "evil.com.mx"), "no coincide si el dominio sigue");
    check(!intel_blocklist_contains_host(bl, ""), "host vacío no coincide");

    printf("\n--- Integración con el reporte ---\n");
    check(url_analyze("https://evil.com/login", &report) == 0, "URL de prueba se analiza");
    check(report.overall == URL_RISK_LOW, "sin lista, la URL queda en bajo riesgo");
    check(intel_apply_blocklist(bl, "https://evil.com/login", &report) == 1, "la lista coincide");
    check(report.overall == URL_RISK_HIGH, "la coincidencia sube el nivel a alto riesgo");
    check(report.finding_count >= 1 &&
          strcmp(report.findings[report.finding_count - 1].indicator, "lista_local_maliciosa") == 0,
          "el hallazgo de la lista aparece con su nombre");

    check(url_analyze("https://google.com/", &report) == 0, "URL limpia se analiza");
    check(intel_apply_blocklist(bl, "https://google.com/", &report) == 0, "URL limpia no coincide");
    check(report.overall == URL_RISK_LOW, "URL limpia sigue en bajo riesgo");

    printf("\n--- Carga desde archivo ---\n");
    f = fopen(TEST_FILE, "w");
    if (f) {
        fprintf(f, "# lista de prueba\n");
        fprintf(f, "malo.example\n");
        fprintf(f, "\n");
        fprintf(f, "phish.example   # comentario al final\n");
        fclose(f);
    }
    {
        Blocklist *from_file = intel_blocklist_new();

        check(from_file != NULL, "segunda lista se crea");
        check(intel_blocklist_load_file(from_file, TEST_FILE, &loaded) == 0, "archivo se lee");
        check(loaded == 2, "se cargan dos dominios (comentarios y líneas vacías se ignoran)");
        check(intel_blocklist_contains_host(from_file, "x.phish.example"),
              "dominio del archivo con comentario al final coincide");
        check(intel_blocklist_load_file(from_file, "no_existe_este_archivo.txt", NULL) != 0,
              "archivo inexistente se reporta como error");
        intel_blocklist_free(from_file);
    }
    remove(TEST_FILE);

    printf("\n--- Listas grandes sin cortes ---\n");
    {
        Blocklist *big = intel_blocklist_new();
        char domain[64];
        size_t added = 0;

        for (size_t i = 0; i < 60000; i++) {
            snprintf(domain, sizeof domain, "dominio%zu.example", i);
            if (intel_blocklist_add(big, domain) == 0)
                added++;
        }
        check(added == 60000, "se aceptan 60000 dominios (más que el antiguo límite de 50000)");
        check(intel_blocklist_size(big) == 60000, "el tamaño refleja todos los dominios");
        check(intel_blocklist_contains_host(big, "www.dominio59999.example"),
              "el último dominio agregado sigue coincidiendo");
        intel_blocklist_free(big);
    }

    intel_blocklist_free(bl);

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
