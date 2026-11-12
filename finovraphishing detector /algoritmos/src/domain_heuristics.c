#include "domain_heuristics.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define MAX_LABELS      32
#define MIN_RANDOM_LEN  10      /* nombres más cortos no se evalúan por entropía */
#define RANDOM_ENTROPY  3.5     /* bits por carácter; los nombres humanos rondan 2.5 a 3 */
#define LONG_NAME_LEN   25

static const char *const GENERIC_SECOND_LEVEL[] = {
    "co", "com", "net", "org", "gob", "gov", "edu", "ac"
};

static const char *const CHEAP_TLDS[] = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip"
};

/* Palabras que suelen aparecer en páginas de robo de credenciales */
static const char *const ACCESS_WORDS[] = {
    "login", "signin", "logon", "verify", "verif", "secure", "seguridad",
    "update", "account", "cuenta", "wallet", "support", "soporte",
    "confirm", "validar", "recover", "recuperar", "clave"
};

static void add_finding(UrlReport *r, const char *indicator, UrlRisk severity,
                        UrlConfidence confidence, const char *reason, const char *evidence)
{
    UrlFinding *f;

    if (r->finding_count >= URL_MAX_FINDINGS)
        return;

    f = &r->findings[r->finding_count++];
    memset(f, 0, sizeof *f);
    snprintf(f->indicator, sizeof f->indicator, "%s", indicator);
    f->severity = severity;
    f->confidence = confidence;
    snprintf(f->reason, sizeof f->reason, "%s", reason);
    snprintf(f->evidence, sizeof f->evidence, "%s", evidence);
}

static bool is_generic(const char *s)
{
    for (size_t i = 0; i < sizeof GENERIC_SECOND_LEVEL / sizeof GENERIC_SECOND_LEVEL[0]; i++) {
        if (strcmp(s, GENERIC_SECOND_LEVEL[i]) == 0)
            return true;
    }
    return false;
}

static bool is_cheap_tld(const char *tld)
{
    for (size_t i = 0; i < sizeof CHEAP_TLDS / sizeof CHEAP_TLDS[0]; i++) {
        if (strcmp(tld, CHEAP_TLDS[i]) == 0)
            return true;
    }
    return false;
}

/* Entropía de Shannon del texto, en bits por carácter */
static double entropy(const char *s, size_t n)
{
    unsigned int freq[256] = {0};
    double h = 0.0;

    if (n == 0)
        return 0.0;
    for (size_t i = 0; i < n; i++)
        freq[(unsigned char)s[i]]++;
    for (size_t c = 0; c < 256; c++) {
        if (freq[c] > 0) {
            double p = (double)freq[c] / (double)n;
            h -= p * log2(p);
        }
    }
    return h;
}

/* Consonantes seguidas (sin contar dígitos ni guiones) */
static size_t longest_consonant_run(const char *s)
{
    size_t best = 0;
    size_t run = 0;

    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)tolower((unsigned char)*p);
        bool vowel = strchr("aeiouy", c) != NULL;

        if (isalpha(c) && !vowel) {
            run++;
            if (run > best)
                best = run;
        } else {
            run = 0;
        }
    }
    return best;
}

void domain_characteristics(const char *host, UrlReport *report)
{
    char work[URL_MAX_HOST];
    char *labels[MAX_LABELS];
    size_t n = 0;
    size_t reg;
    const char *tld;
    const char *name;
    size_t len;
    size_t digits = 0;
    char lower[URL_MAX_HOST];
    char evidence[URL_TEXT_LEN];
    char reason[URL_TEXT_LEN];

    if (!host || !report || host[0] == '\0')
        return;

    snprintf(work, sizeof work, "%s", host);
    labels[n++] = work;
    for (char *p = work; n < MAX_LABELS && (p = strchr(p, '.')) != NULL;) {
        *p = '\0';
        p++;
        labels[n++] = p;
    }
    if (n < 2 || n >= MAX_LABELS)
        return;

    /* Dominios de dirección IP no tienen nombre que evaluar */
    if (isdigit((unsigned char)labels[n - 1][0]))
        return;

    tld = labels[n - 1];
    reg = n - 2;
    if (n >= 3 && strlen(tld) == 2 && is_generic(labels[n - 2]))
        reg = n - 3;

    name = labels[reg];
    len = strlen(name);
    snprintf(lower, sizeof lower, "%s", name);
    for (char *p = lower; *p; p++)
        *p = (char)tolower((unsigned char)*p);

    for (const char *p = lower; *p; p++) {
        if (isdigit((unsigned char)*p))
            digits++;
    }

    /* Tld de registro barato */
    if (is_cheap_tld(tld)) {
        snprintf(reason, sizeof reason,
                 "El dominio usa una extensión de registro barato (.%s), muy común en campañas.", tld);
        snprintf(evidence, sizeof evidence, "tld='%s'", tld);
        add_finding(report, "tld_de_registro_barato", URL_RISK_LOW, URL_CONFIDENCE_MEDIUM, reason, evidence);
    }

    /* Nombre con apariencia aleatoria */
    if (len >= MIN_RANDOM_LEN && entropy(lower, len) >= RANDOM_ENTROPY) {
        if (digits >= 2) {
            snprintf(reason, sizeof reason,
                     "El nombre parece generado al azar y mezcla letras con dígitos.");
            snprintf(evidence, sizeof evidence, "nombre='%s', entropía=%.2f", name, entropy(lower, len));
            add_finding(report, "nombre_aleatorio_con_digitos", URL_RISK_SUSPICIOUS,
                        URL_CONFIDENCE_MEDIUM, reason, evidence);
        } else {
            snprintf(reason, sizeof reason, "El nombre tiene una apariencia poco natural (muy irregular).");
            snprintf(evidence, sizeof evidence, "nombre='%s', entropía=%.2f", name, entropy(lower, len));
            add_finding(report, "nombre_aleatorio", URL_RISK_LOW, URL_CONFIDENCE_LOW, reason, evidence);
        }
    }

    /* Muchos dígitos */
    if (len >= 6 && digits * 10 >= len * 4) {
        snprintf(reason, sizeof reason,
                 "Más del 40%% del nombre son dígitos, algo poco común en marcas legítimas.");
        snprintf(evidence, sizeof evidence, "nombre='%s', dígitos=%zu de %zu", name, digits, len);
        add_finding(report, "digitos_excesivos", URL_RISK_LOW, URL_CONFIDENCE_LOW, reason, evidence);
    }

    /* Consonantes seguidas: palabras pronunciables casi nunca las tienen */
    if (longest_consonant_run(lower) >= 6) {
        snprintf(reason, sizeof reason, "El nombre tiene una secuencia larga de consonantes sin vocales.");
        snprintf(evidence, sizeof evidence, "nombre='%s'", name);
        add_finding(report, "consonantes_seguidas", URL_RISK_LOW, URL_CONFIDENCE_LOW, reason, evidence);
    }

    /* Nombre muy largo */
    if (len >= LONG_NAME_LEN) {
        snprintf(reason, sizeof reason, "El nombre del dominio es inusualmente largo.");
        snprintf(evidence, sizeof evidence, "nombre de %zu caracteres", len);
        add_finding(report, "nombre_muy_largo", URL_RISK_LOW, URL_CONFIDENCE_LOW, reason, evidence);
    }

    /* Palabras de acceso o presión: una sola observación aunque aparezcan varias */
    for (size_t i = 0; i < sizeof ACCESS_WORDS / sizeof ACCESS_WORDS[0]; i++) {
        if (strstr(lower, ACCESS_WORDS[i]) != NULL) {
            snprintf(reason, sizeof reason,
                     "El nombre contiene una palabra típica de páginas de acceso o de presión (%s).",
                     ACCESS_WORDS[i]);
            snprintf(evidence, sizeof evidence, "nombre='%s'", name);
            add_finding(report, "palabra_de_acceso", URL_RISK_LOW, URL_CONFIDENCE_MEDIUM, reason, evidence);
            break;
        }
    }
}
