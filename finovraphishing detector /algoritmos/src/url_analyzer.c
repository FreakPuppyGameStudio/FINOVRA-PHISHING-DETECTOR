#include "url_analyzer.h"
#include "domain_heuristics.h"
#include "risk_engine.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRAND_MIN_LEN   5    /* marcas más cortas generan demasiadas coincidencias falsas */
#define MAX_LABELS      32
#define MAX_AUTHORITY   512
#define MAX_LABEL_LEN   64

/* Marcas muy suplantadas. Se pueden ampliar sin tocar la lógica. */
static const char *KNOWN_BRANDS[] = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "santander", "bbva",
    "bancomer", "banorte", "mercadolibre"
};
#define BRAND_COUNT (sizeof KNOWN_BRANDS / sizeof KNOWN_BRANDS[0])

/* Acortadores: ocultan el destino real */
static const char *URL_SHORTENERS[] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"
};
#define SHORTENER_COUNT (sizeof URL_SHORTENERS / sizeof URL_SHORTENERS[0])

/* Dominios de registro barato, muy usados en campañas de phishing */
static const char *SUSPICIOUS_TLDS[] = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip"
};
#define SUSPICIOUS_TLD_COUNT (sizeof SUSPICIOUS_TLDS / sizeof SUSPICIOUS_TLDS[0])

typedef enum {
    MATCH_NONE,
    MATCH_NEAR,     /* parecido a la marca (1 o 2 letras de diferencia) */
    MATCH_EXACT     /* igual a la marca */
} MatchKind;

/* ------------------------------------------------------------------ */
/* Utilidades de texto                                                 */
/* ------------------------------------------------------------------ */

/* Copia segura: trunca si no cabe y siempre termina en '\0'. */
static void copy_str(char *dst, size_t size, const char *src)
{
    size_t n = strlen(src);

    if (size == 0)
        return;
    if (n >= size)
        n = size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool is_ipv4(const char *host)
{
    int groups = 0;
    const char *p = host;

    while (*p) {
        int digits = 0;
        int value = 0;

        while (isdigit((unsigned char)*p)) {
            value = value * 10 + (*p - '0');
            digits++;
            p++;
        }
        if (digits == 0 || digits > 3 || value > 255)
            return false;

        groups++;
        if (*p == '.')
            p++;
        else if (*p != '\0')
            return false;
    }
    return groups == 4;
}

/* true si host es domain o termina en ".domain" */
static bool host_ends_with(const char *host, const char *domain)
{
    size_t hl = strlen(host);
    size_t dl = strlen(domain);

    if (hl == dl)
        return strcmp(host, domain) == 0;
    return hl > dl && host[hl - dl - 1] == '.' && strcmp(host + hl - dl, domain) == 0;
}

static bool is_shortener(const char *host)
{
    for (size_t i = 0; i < SHORTENER_COUNT; i++) {
        if (host_ends_with(host, URL_SHORTENERS[i]))
            return true;
    }
    return false;
}

static bool is_suspicious_tld(const char *tld)
{
    for (size_t i = 0; i < SUSPICIOUS_TLD_COUNT; i++) {
        if (strcmp(tld, SUSPICIOUS_TLDS[i]) == 0)
            return true;
    }
    return false;
}

/* Segundo nivel genérico de países (ej. google.co.uk): el dominio real es la etiqueta anterior */
static bool is_generic_second_level(const char *s)
{
    static const char *list[] = {"co", "com", "net", "org", "gob", "gov", "edu", "ac"};

    for (size_t i = 0; i < sizeof list / sizeof list[0]; i++) {
        if (strcmp(s, list[i]) == 0)
            return true;
    }
    return false;
}

/* %xx con dígitos hexadecimales */
static bool has_percent_escape(const char *s)
{
    for (const char *p = s; *p; p++) {
        if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2]))
            return true;
    }
    return false;
}

static bool has_non_ascii(const char *s)
{
    for (const char *p = s; *p; p++) {
        if ((unsigned char)*p > 127)
            return true;
    }
    return false;
}

static bool host_chars_valid(const char *host)
{
    for (const char *p = host; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || isspace(c) || c == '[' || c == ']' || c == '\\')
            return false;
    }
    return true;
}

/* Divide el host en etiquetas separadas por '.'. Modifica la cadena. */
static size_t split_labels(char *host, char *labels[])
{
    size_t n = 0;
    char *p = host;

    labels[n++] = p;
    while (n < MAX_LABELS && (p = strchr(p, '.')) != NULL) {
        *p = '\0';
        p++;
        labels[n++] = p;
    }
    return n;
}

int url_levenshtein(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int prev[MAX_LABEL_LEN];
    int cur[MAX_LABEL_LEN];

    if (la >= MAX_LABEL_LEN || lb >= MAX_LABEL_LEN)
        return 1000;

    for (size_t j = 0; j <= lb; j++)
        prev[j] = (int)j;

    for (size_t i = 1; i <= la; i++) {
        cur[0] = (int)i;
        for (size_t j = 1; j <= lb; j++) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int del = prev[j] + 1;
            int ins = cur[j - 1] + 1;
            int sub = prev[j - 1] + cost;
            int m = del < ins ? del : ins;
            cur[j] = m < sub ? m : sub;
        }
        memcpy(prev, cur, (lb + 1) * sizeof(int));
    }
    return prev[lb];
}

/*
 * Compara cada parte de una etiqueta (separada por '-') con una marca.
 * "paypa1-login" contiene la parte "paypa1", que se parece a "paypal".
 */
static MatchKind label_brand_match(const char *label, const char *brand)
{
    char tmp[URL_MAX_HOST];
    char *tok;
    size_t bl = strlen(brand);
    MatchKind best = MATCH_NONE;

    snprintf(tmp, sizeof tmp, "%s", label);
    tok = tmp;

    while (tok) {
        char *dash = strchr(tok, '-');
        size_t tl;

        if (dash)
            *dash = '\0';
        tl = strlen(tok);

        if (strcmp(tok, brand) == 0) {
            return MATCH_EXACT;
        } else {
            size_t diff = tl > bl ? tl - bl : bl - tl;

            if (diff <= 1) {
                int dist = url_levenshtein(tok, brand);
                if (dist >= 1 && dist <= 2)
                    best = MATCH_NEAR;
            }
        }

        tok = dash ? dash + 1 : NULL;
    }
    return best;
}

/* ------------------------------------------------------------------ */
/* Parser                                                              */
/* ------------------------------------------------------------------ */

bool url_parse(const char *input, UrlParts *out)
{
    char buf[URL_MAX_INPUT];
    char authority[MAX_AUTHORITY];
    const char *start = NULL;
    const char *scheme_sep;
    const char *s;
    size_t len;
    size_t auth_len;
    char *hostport;
    char *at;
    char *colon;

    if (!input || !out)
        return false;

    memset(out, 0, sizeof *out);
    out->port = -1;

    if (strlen(input) >= URL_MAX_INPUT)
        return false;

    /* Quitar espacios al inicio y al final */
    snprintf(buf, sizeof buf, "%s", input);
    s = buf;
    while (isspace((unsigned char)*s))
        s++;
    memmove(buf, s, strlen(s) + 1);
    len = strlen(buf);
    while (len > 0 && isspace((unsigned char)buf[len - 1]))
        buf[--len] = '\0';
    if (len == 0)
        return false;

    /* Esquema (opcional) */
    start = buf;
    scheme_sep = strstr(buf, "://");
    if (scheme_sep) {
        size_t sl = (size_t)(scheme_sep - buf);
        if (sl == 0 || sl >= sizeof out->scheme)
            return false;
        memcpy(out->scheme, buf, sl);
        out->scheme[sl] = '\0';
        start = scheme_sep + 3;
    }

    /* Autoridad: lo que va antes de '/', '?' o '#' */
    auth_len = strcspn(start, "/?#");
    if (auth_len == 0 || auth_len >= sizeof authority)
        return false;
    memcpy(authority, start, auth_len);
    authority[auth_len] = '\0';
    snprintf(out->path, sizeof out->path, "%s", start + auth_len);

    /* Usuario (texto antes de '@'). El host real es lo que sigue al último '@'. */
    hostport = authority;
    at = strrchr(authority, '@');
    if (at) {
        *at = '\0';
        out->has_userinfo = true;
        copy_str(out->userinfo, sizeof out->userinfo, authority);
        hostport = at + 1;
    }

    /* Puerto */
    colon = strrchr(hostport, ':');
    if (colon) {
        const char *d = colon + 1;
        long port;

        if (*d == '\0')
            return false;
        for (; *d; d++) {
            if (!isdigit((unsigned char)*d))
                return false;
        }
        port = strtol(colon + 1, NULL, 10);
        if (port < 1 || port > 65535)
            return false;
        out->port = (int)port;
        *colon = '\0';
    }

    if (hostport[0] == '\0' || strlen(hostport) >= URL_MAX_HOST || !host_chars_valid(hostport))
        return false;

    for (char *h = hostport; *h; h++)
        *h = (char)tolower((unsigned char)*h);

    /* Quitar el punto final absoluto (ejemplo.com.) */
    len = strlen(hostport);
    if (len > 1 && hostport[len - 1] == '.')
        hostport[len - 1] = '\0';

    copy_str(out->host, sizeof out->host, hostport);
    return true;
}

/* ------------------------------------------------------------------ */
/* Hallazgos                                                           */
/* ------------------------------------------------------------------ */

static void add_finding(UrlReport *r, const char *indicator, UrlRisk severity,
                        UrlConfidence confidence, const char *reason, const char *evidence)
{
    UrlFinding *f;

    if (r->finding_count >= URL_MAX_FINDINGS)
        return;

    f = &r->findings[r->finding_count++];
    snprintf(f->indicator, sizeof f->indicator, "%s", indicator);
    f->severity = severity;
    f->confidence = confidence;
    snprintf(f->reason, sizeof f->reason, "%s", reason);
    snprintf(f->evidence, sizeof f->evidence, "%s", evidence);
}

/*
 * Analiza los indicadores propios de un dominio.
 * Devuelve true si el host imita o contiene una marca conocida.
 */
static bool analyze_domain(UrlReport *r)
{
    UrlParts *p = &r->parts;
    char work[URL_MAX_HOST];
    char *labels[MAX_LABELS];
    size_t n;
    size_t reg;
    size_t subdomains;
    const char *tld;
    const char *brand = "";
    const char *hyphen_label = NULL;
    MatchKind mk = MATCH_NONE;
    size_t mi = 0;
    bool found = false;
    bool brand_hit = false;
    bool has_hyphen = false;
    char text[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];

    snprintf(work, sizeof work, "%s", p->host);
    n = split_labels(work, labels);
    if (n < 2 || n >= MAX_LABELS)
        return false;

    tld = labels[n - 1];

    /* Etiqueta que identifica al dueño del dominio (la "registrable") */
    reg = n - 2;
    if (n >= 3 && strlen(tld) == 2 && is_generic_second_level(labels[n - 2]))
        reg = n - 3;
    subdomains = reg;

    snprintf(evidence, sizeof evidence, "host='%s'", p->host);

    /* 1. Marca conocida: exacta o parecida, en cualquier etiqueta excepto el TLD */
    for (size_t i = 0; i + 1 < n && !found; i++) {
        for (size_t b = 0; b < BRAND_COUNT && !found; b++) {
            MatchKind k;

            if (strlen(KNOWN_BRANDS[b]) < BRAND_MIN_LEN)
                continue;
            k = label_brand_match(labels[i], KNOWN_BRANDS[b]);
            if (k == MATCH_NONE)
                continue;

            /* El dominio oficial de la marca (paypal.com) no es sospechoso */
            if (k == MATCH_EXACT && i == reg && strcmp(labels[i], KNOWN_BRANDS[b]) == 0)
                continue;

            found = true;
            mk = k;
            mi = i;
            brand = KNOWN_BRANDS[b];
        }
    }

    if (found) {
        bool in_subdomain = mi < reg;

        brand_hit = true;

        /* Marca exacta dentro de una parte de dominio ajena (el caso del subdominio falso)
         * o una imitación de pocas letras: son indicadores de atención. */
        if (mk == MATCH_NEAR || in_subdomain) {
            UrlRisk sev = is_suspicious_tld(tld) ? URL_RISK_HIGH : URL_RISK_SUSPICIOUS;
            UrlConfidence conf = (mk == MATCH_EXACT) ? URL_CONFIDENCE_HIGH : URL_CONFIDENCE_MEDIUM;

            if (mk == MATCH_NEAR) {
                snprintf(text, sizeof text,
                         "El nombre del dominio se parece a la marca '%s' (pocas letras de diferencia).",
                         brand);
            } else {
                snprintf(text, sizeof text,
                         "La marca '%s' aparece en un subdominio, pero el dominio real es otro.",
                         brand);
            }

            if (is_suspicious_tld(tld))
                strncat(text, " Además usa un dominio de registro muy barato.",
                        sizeof text - strlen(text) - 1);

            add_finding(r, "marca_suplantada", sev, conf, text, evidence);
        }
    }

    /* 2. Guiones en el dominio (se ignoran los punycode xn--) */
    for (size_t i = 0; i + 1 < n; i++) {
        if (strncmp(labels[i], "xn--", 4) != 0 && strchr(labels[i], '-') != NULL) {
            has_hyphen = true;
            hyphen_label = labels[i];
            break;
        }
    }
    if (has_hyphen) {
        UrlRisk sev = brand_hit ? URL_RISK_SUSPICIOUS : URL_RISK_LOW;
        UrlConfidence conf = brand_hit ? URL_CONFIDENCE_MEDIUM : URL_CONFIDENCE_LOW;

        if (brand_hit) {
            snprintf(text, sizeof text,
                     "Guiones en '%s' junto a una marca conocida ('%s').", hyphen_label, brand);
        } else {
            snprintf(text, sizeof text,
                     "Guiones en '%s'. Es común, pero también se usa para imitar sitios.",
                     hyphen_label);
        }
        add_finding(r, "guiones_en_dominio", sev, conf, text, evidence);
    }

    /* 3. Demasiados subdominios (3 o más) */
    if (subdomains >= 3) {
        UrlRisk sev = brand_hit ? URL_RISK_SUSPICIOUS : URL_RISK_LOW;
        UrlConfidence conf = brand_hit ? URL_CONFIDENCE_MEDIUM : URL_CONFIDENCE_LOW;

        snprintf(text, sizeof text,
                 "El dominio tiene %zu subdominios antes del nombre principal.", subdomains);
        add_finding(r, "subdominios_excesivos", sev, conf, text, evidence);
    }

    return brand_hit;
}

/* Regla general: un débil nunca basta; tres sospechosos o cualquier alto dan riesgo alto. */
static UrlRisk compute_overall(const UrlReport *r)
{
    return risk_aggregate(r->findings, r->finding_count);
}

/* ------------------------------------------------------------------ */
/* Análisis principal                                                  */
/* ------------------------------------------------------------------ */

int url_analyze(const char *input, UrlReport *report)
{
    UrlParts *p;
    bool brand_hit = false;
    char text[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];

    if (!input || !report)
        return -1;

    memset(report, 0, sizeof *report);
    if (!url_parse(input, &report->parts))
        return -1;
    p = &report->parts;

    /* Usuario antes de '@': truco clásico para aparentar otro sitio */
    if (p->has_userinfo) {
        snprintf(text, sizeof text,
                 "La URL tiene texto antes del '@'. Ese texto no es el destino: el navegador se conecta a '%s'.",
                 p->host);
        snprintf(evidence, sizeof evidence, "usuario='%s', host='%s'", p->userinfo, p->host);
        add_finding(report, "credenciales_en_url", URL_RISK_HIGH, URL_CONFIDENCE_HIGH, text, evidence);
    }

    /* Acortadores */
    if (is_shortener(p->host)) {
        snprintf(text, sizeof text, "Es un acortador de URL: oculta el destino real hasta abrirla.");
        snprintf(evidence, sizeof evidence, "host='%s'", p->host);
        add_finding(report, "acortador_url", URL_RISK_SUSPICIOUS, URL_CONFIDENCE_HIGH, text, evidence);
    }

    /* Dirección IP en lugar de dominio */
    if (is_ipv4(p->host)) {
        bool odd_port = p->port != -1 && p->port != 80 && p->port != 443;

        if (p->port != -1)
            snprintf(evidence, sizeof evidence, "host='%s', puerto=%d", p->host, p->port);
        else
            snprintf(evidence, sizeof evidence, "host='%s'", p->host);

        if (odd_port) {
            snprintf(text, sizeof text,
                     "Dirección IP con puerto no estándar: patrón típico de páginas improvisadas de phishing.");
            add_finding(report, "ip_en_lugar_de_dominio", URL_RISK_HIGH, URL_CONFIDENCE_HIGH, text, evidence);
        } else {
            snprintf(text, sizeof text, "Se usa una dirección IP en lugar de un nombre de dominio.");
            add_finding(report, "ip_en_lugar_de_dominio", URL_RISK_SUSPICIOUS, URL_CONFIDENCE_HIGH, text, evidence);
        }
    } else {
        brand_hit = analyze_domain(report);
        domain_characteristics(p->host, report);
    }

    /* Caracteres codificados (%xx), Unicode y punycode */
    if (has_percent_escape(input) || has_non_ascii(input) || strstr(p->host, "xn--") != NULL) {
        bool puny = strstr(p->host, "xn--") != NULL;
        UrlRisk sev = (puny && brand_hit) ? URL_RISK_HIGH : URL_RISK_SUSPICIOUS;

        if (puny) {
            snprintf(text, sizeof text,
                     "El dominio usa punycode (xn--), que puede mostrar letras que imitan a otras.");
        } else {
            snprintf(text, sizeof text,
                     "La URL usa caracteres codificados (%%xx) o Unicode, que pueden ocultar el destino.");
        }
        snprintf(evidence, sizeof evidence, "host='%s'", p->host);
        add_finding(report, "codificacion_caracteres", sev, URL_CONFIDENCE_MEDIUM, text, evidence);
    }

    report->overall = compute_overall(report);
    return 0;
}

const char *url_risk_name(UrlRisk risk)
{
    switch (risk) {
    case URL_RISK_LOW:
        return "Bajo riesgo";
    case URL_RISK_SUSPICIOUS:
        return "Sospechosa";
    case URL_RISK_HIGH:
        return "Alto riesgo";
    }
    return "Desconocido";
}

const char *url_known_brand(const char *word)
{
    for (size_t b = 0; b < BRAND_COUNT; b++) {
        if (strcmp(word, KNOWN_BRANDS[b]) == 0)
            return KNOWN_BRANDS[b];
    }
    return NULL;
}
