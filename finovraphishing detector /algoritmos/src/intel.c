#include "intel.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "risk_engine.h"

#define LINE_LEN 512

struct Blocklist {
    char **domains;     /* cada dominio es una cadena propia en memoria */
    size_t count;
    size_t capacity;
};

Blocklist *intel_blocklist_new(void)
{
    return calloc(1, sizeof(Blocklist));
}

void intel_blocklist_free(Blocklist *bl)
{
    if (!bl)
        return;
    for (size_t i = 0; i < bl->count; i++)
        free(bl->domains[i]);
    free(bl->domains);
    free(bl);
}

size_t intel_blocklist_size(const Blocklist *bl)
{
    return bl ? bl->count : 0;
}

/* Sin espacios, en minúsculas, sin punto final */
static bool normalize_domain(const char *in, char *out, size_t size)
{
    size_t n = 0;

    while (*in && isspace((unsigned char)*in))
        in++;
    while (*in && !isspace((unsigned char)*in) && n + 1 < size) {
        out[n++] = (char)tolower((unsigned char)*in);
        in++;
    }
    while (n > 0 && out[n - 1] == '.')
        n--;
    out[n] = '\0';
    return n > 0;
}

/* Duplica la capacidad del arreglo, hasta el límite de seguridad */
static int grow(Blocklist *bl)
{
    size_t cap = bl->capacity ? bl->capacity * 2 : 1024;
    char **nd;

    if (cap > INTEL_MAX_DOMAINS)
        cap = INTEL_MAX_DOMAINS;
    if (cap <= bl->capacity)
        return -1;

    nd = realloc(bl->domains, cap * sizeof *nd);
    if (!nd)
        return -1;
    bl->domains = nd;
    bl->capacity = cap;
    return 0;
}

int intel_blocklist_add(Blocklist *bl, const char *domain)
{
    char norm[INTEL_DOMAIN_LEN];
    size_t len;
    char *copy;

    if (!bl || !domain)
        return -1;
    if (!normalize_domain(domain, norm, sizeof norm))
        return -1;
    if (strchr(norm, '/') || strchr(norm, ':'))
        return -1;

    if (bl->count == bl->capacity && grow(bl) != 0)
        return -1;

    len = strlen(norm);
    copy = malloc(len + 1);
    if (!copy)
        return -1;
    memcpy(copy, norm, len + 1);
    bl->domains[bl->count++] = copy;
    return 0;
}

int intel_blocklist_load_file(Blocklist *bl, const char *path, size_t *loaded)
{
    FILE *f;
    char line[LINE_LEN];
    size_t added = 0;

    if (loaded)
        *loaded = 0;
    if (!bl || !path)
        return -1;

    f = fopen(path, "r");
    if (!f)
        return -1;

    while (fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');

        if (hash)
            *hash = '\0';
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (intel_blocklist_add(bl, line) == 0)
            added++;
    }

    fclose(f);
    if (loaded)
        *loaded = added;
    return 0;
}

/* Servidor de una URL: "https://sitio.com:8080/x" -> "sitio.com" */
static void host_of_url(const char *url, char *host, size_t size)
{
    const char *p = strstr(url, "://");
    size_t n = 0;

    p = p ? p + 3 : url;
    while (p[n] && p[n] != '/' && p[n] != ':' && p[n] != '?' && p[n] != '#' && p[n] != '@')
        n++;
    if (n >= size)
        n = size - 1;
    memcpy(host, p, n);
    host[n] = '\0';
    for (char *h = host; *h; h++)
        *h = (char)tolower((unsigned char)*h);
}

bool intel_blocklist_contains_host(const Blocklist *bl, const char *host)
{
    size_t hl;

    if (!bl || !host || host[0] == '\0')
        return false;
    hl = strlen(host);

    for (size_t i = 0; i < bl->count; i++) {
        const char *d = bl->domains[i];
        size_t dl = strlen(d);

        if (hl == dl && strcmp(host, d) == 0)
            return true;
        /* subdominio: el host termina en ".dominio" */
        if (hl > dl && host[hl - dl - 1] == '.' && strcmp(host + hl - dl, d) == 0)
            return true;
    }
    return false;
}

int intel_apply_blocklist(const Blocklist *bl, const char *url, UrlReport *report)
{
    char host[INTEL_DOMAIN_LEN];
    char evidence[URL_TEXT_LEN];
    UrlFinding *f;

    if (!bl || !url || !report)
        return 0;

    host_of_url(url, host, sizeof host);
    if (!intel_blocklist_contains_host(bl, host))
        return 0;

    if (report->finding_count < URL_MAX_FINDINGS) {
        f = &report->findings[report->finding_count++];
        memset(f, 0, sizeof *f);
        snprintf(f->indicator, sizeof f->indicator, "lista_local_maliciosa");
        snprintf(f->reason, sizeof f->reason,
                 "El dominio aparece en tu lista local de dominios maliciosos.");
        snprintf(evidence, sizeof evidence, "host='%s', fuente=lista local", host);
        snprintf(f->evidence, sizeof f->evidence, "%s", evidence);
        f->severity = URL_RISK_HIGH;
        f->confidence = URL_CONFIDENCE_HIGH;
    }

    report->overall = risk_aggregate(report->findings, report->finding_count);
    return 1;
}
