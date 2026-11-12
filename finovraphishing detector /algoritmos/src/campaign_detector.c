#include "campaign_detector.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "url_analyzer.h"

#define MAX_BRANDS      8
#define MAX_WORDS       128
#define WORD_LEN        32
#define MIN_BODY_WORDS  10      /* textos más cortos no se comparan por palabras */
#define NO_CAMPAIGN     ((size_t)-1)

/* Datos precalculados de cada correo, para no repetir el trabajo en cada comparación */
typedef struct {
    char subject[EMAIL_FIELD_LEN];          /* asunto normalizado */
    char sender[EMAIL_FIELD_LEN];           /* dirección del remitente en minúsculas */
    char sender_domain[EMAIL_FIELD_LEN];
    char brands[MAX_BRANDS][WORD_LEN];      /* marcas conocidas mencionadas */
    size_t brand_count;
    char words[MAX_WORDS][WORD_LEN];        /* palabras distintas del cuerpo */
    size_t word_count;
} Profile;

typedef struct {
    size_t a;
    size_t b;
    unsigned int flags;
} PairLink;

static const struct {
    unsigned int bit;
    const char *name;
} SIGNAL_NAMES[] = {
    {CAMPAIGN_SIG_SHARED_URL,         "enlace idéntico"},
    {CAMPAIGN_SIG_SHARED_HOST,        "mismo servidor de enlace"},
    {CAMPAIGN_SIG_SAME_SENDER,        "mismo remitente"},
    {CAMPAIGN_SIG_SAME_SENDER_DOMAIN, "mismo dominio de remitente"},
    {CAMPAIGN_SIG_SUBJECT_EQUAL,      "mismo asunto"},
    {CAMPAIGN_SIG_SUBJECT_SIMILAR,    "asunto parecido"},
    {CAMPAIGN_SIG_BODY_SIMILAR,       "texto parecido"},
    {CAMPAIGN_SIG_SHARED_BRAND,       "misma marca mencionada"}
};
#define SIGNAL_COUNT (sizeof SIGNAL_NAMES / sizeof SIGNAL_NAMES[0])

/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

static void lower_copy(char *dst, size_t size, const char *src)
{
    size_t n = 0;

    if (size == 0)
        return;
    while (src[n] && n + 1 < size) {
        dst[n] = (char)tolower((unsigned char)src[n]);
        n++;
    }
    dst[n] = '\0';
}

/*
 * Siguiente palabra (letras y dígitos) desde *pos, en minúsculas.
 * Devuelve false cuando ya no hay más.
 */
static bool next_token(const char *s, size_t len, size_t *pos, char *tok, size_t tsize)
{
    size_t i = *pos;
    size_t n = 0;

    while (i < len && !isalnum((unsigned char)s[i]))
        i++;
    if (i >= len) {
        *pos = i;
        return false;
    }
    while (i < len && isalnum((unsigned char)s[i])) {
        if (n + 1 < tsize)
            tok[n++] = (char)tolower((unsigned char)s[i]);
        i++;
    }
    tok[n] = '\0';
    *pos = i;
    return true;
}

/* Quita "re:", "fw:", "fwd:" y espacios; deja solo letras, dígitos y espacios simples */
static void normalize_subject(const char *in, char *out, size_t size)
{
    char tmp[EMAIL_FIELD_LEN];
    const char *p;
    size_t o = 0;

    lower_copy(tmp, sizeof tmp, in);
    p = tmp;

    for (;;) {
        while (*p == ' ')
            p++;
        if (strncmp(p, "re:", 3) == 0)
            p += 3;
        else if (strncmp(p, "fwd:", 4) == 0)
            p += 4;
        else if (strncmp(p, "fw:", 3) == 0)
            p += 3;
        else if (strncmp(p, "rv:", 3) == 0)
            p += 3;
        else
            break;
    }

    for (; *p && o + 1 < size; p++) {
        if (isalnum((unsigned char)*p)) {
            out[o++] = *p;
        } else if (*p == ' ' && o > 0 && out[o - 1] != ' ') {
            out[o++] = ' ';
        }
    }
    while (o > 0 && out[o - 1] == ' ')
        o--;
    out[o] = '\0';
}

/* Separa la dirección y el dominio de un campo From, p. ej. "Nombre <correo@dominio>" */
static void sender_parts(const char *from, char *addr, size_t asize, char *dom, size_t dsize)
{
    const char *lt = strchr(from, '<');
    const char *gt = lt ? strchr(lt, '>') : NULL;
    char tmp[EMAIL_FIELD_LEN];
    const char *at;

    if (lt && gt) {
        size_t n = (size_t)(gt - lt - 1);

        if (n >= sizeof tmp)
            n = sizeof tmp - 1;
        memcpy(tmp, lt + 1, n);
        tmp[n] = '\0';
    } else {
        lower_copy(tmp, sizeof tmp, from);
    }

    lower_copy(addr, asize, tmp);
    at = strrchr(addr, '@');
    if (at)
        lower_copy(dom, dsize, at + 1);
    else
        dom[0] = '\0';
}

/* Servidor de una URL: "https://sitio.com/x" -> "sitio.com" */
static void host_of_url(const char *url, char *host, size_t size)
{
    const char *p = strstr(url, "://");
    size_t n = 0;

    p = p ? p + 3 : url;
    while (p[n] && p[n] != '/' && p[n] != ':' && p[n] != '?' && p[n] != '#')
        n++;
    if (n >= size)
        n = size - 1;
    memcpy(host, p, n);
    host[n] = '\0';
    for (char *h = host; *h; h++)
        *h = (char)tolower((unsigned char)*h);
}

static bool profile_has_brand(const Profile *p, const char *brand)
{
    for (size_t i = 0; i < p->brand_count; i++) {
        if (strcmp(p->brands[i], brand) == 0)
            return true;
    }
    return false;
}

/* Marcas conocidas en un texto (nombre, asunto), sin duplicados */
static void collect_brands(const char *text, Profile *p)
{
    char tok[WORD_LEN];
    size_t pos = 0;
    size_t len = strlen(text);

    while (next_token(text, len, &pos, tok, sizeof tok)) {
        if (strlen(tok) >= 5 && url_known_brand(tok) && !profile_has_brand(p, tok)
            && p->brand_count < MAX_BRANDS) {
            strncpy(p->brands[p->brand_count], tok, WORD_LEN - 1);
            p->brands[p->brand_count][WORD_LEN - 1] = '\0';
            p->brand_count++;
        }
    }
}

/* Palabras distintas de 4 letras o más en el cuerpo, con límite */
static void collect_words(const char *body, size_t len, Profile *p)
{
    char tok[WORD_LEN];
    size_t pos = 0;

    while (next_token(body, len, &pos, tok, sizeof tok)) {
        bool seen = false;

        if (strlen(tok) < 4 || p->word_count >= MAX_WORDS)
            continue;
        for (size_t i = 0; i < p->word_count; i++) {
            if (strcmp(p->words[i], tok) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            strncpy(p->words[p->word_count], tok, WORD_LEN - 1);
            p->words[p->word_count][WORD_LEN - 1] = '\0';
            p->word_count++;
        }
    }
}

static void build_profile(const EmailMessage *m, Profile *p)
{
    normalize_subject(m->subject, p->subject, sizeof p->subject);
    sender_parts(m->from, p->sender, sizeof p->sender, p->sender_domain, sizeof p->sender_domain);
    collect_brands(m->from, p);
    collect_brands(m->subject, p);
    collect_words(m->body, m->body_len, p);
}

/* ------------------------------------------------------------------ */
/* Comparación de pares                                                */
/* ------------------------------------------------------------------ */

/* Dos textos comparten la mitad o más de sus palabras */
static bool body_similar(const Profile *a, const Profile *b)
{
    size_t common = 0;
    size_t union_size;

    if (a->word_count == 0 || b->word_count == 0)
        return false;

    for (size_t i = 0; i < a->word_count; i++) {
        for (size_t j = 0; j < b->word_count; j++) {
            if (strcmp(a->words[i], b->words[j]) == 0) {
                common++;
                break;
            }
        }
    }

    union_size = a->word_count + b->word_count - common;
    return union_size >= MIN_BODY_WORDS && common * 2 >= union_size;
}

static unsigned int compare_profiles(const EmailMessage *ma, const Profile *pa,
                                     const EmailMessage *mb, const Profile *pb)
{
    unsigned int f = 0;

    /* Enlaces: el mismo enlace exacto pesa más que el mismo servidor */
    for (size_t i = 0; i < ma->url_count; i++) {
        char host_a[EMAIL_URL_LEN];

        host_of_url(ma->urls[i], host_a, sizeof host_a);
        for (size_t j = 0; j < mb->url_count; j++) {
            char host_b[EMAIL_URL_LEN];

            if (strcmp(ma->urls[i], mb->urls[j]) == 0) {
                f |= CAMPAIGN_SIG_SHARED_URL;
            } else {
                host_of_url(mb->urls[j], host_b, sizeof host_b);
                if (host_a[0] && strcmp(host_a, host_b) == 0)
                    f |= CAMPAIGN_SIG_SHARED_HOST;
            }
        }
    }

    /* Remitente: misma dirección, o al menos mismo dominio */
    if (pa->sender[0] && strcmp(pa->sender, pb->sender) == 0)
        f |= CAMPAIGN_SIG_SAME_SENDER;
    else if (pa->sender_domain[0] && strcmp(pa->sender_domain, pb->sender_domain) == 0)
        f |= CAMPAIGN_SIG_SAME_SENDER_DOMAIN;

    /* Asunto */
    if (strlen(pa->subject) >= 5 && strcmp(pa->subject, pb->subject) == 0) {
        f |= CAMPAIGN_SIG_SUBJECT_EQUAL;
    } else if (strlen(pa->subject) >= 10 && strlen(pb->subject) >= 10 &&
               url_levenshtein(pa->subject, pb->subject) <= 2) {
        f |= CAMPAIGN_SIG_SUBJECT_SIMILAR;
    }

    if (body_similar(pa, pb))
        f |= CAMPAIGN_SIG_BODY_SIMILAR;

    for (size_t i = 0; i < pa->brand_count; i++) {
        if (profile_has_brand(pb, pa->brands[i])) {
            f |= CAMPAIGN_SIG_SHARED_BRAND;
            break;
        }
    }

    return f;
}

static int pair_score(unsigned int f)
{
    int s = 0;

    if (f & CAMPAIGN_SIG_SHARED_URL)         s += 3;
    if (f & CAMPAIGN_SIG_SHARED_HOST)        s += 2;
    if (f & CAMPAIGN_SIG_SAME_SENDER)        s += 2;
    if (f & CAMPAIGN_SIG_SAME_SENDER_DOMAIN) s += 1;
    if (f & CAMPAIGN_SIG_SUBJECT_EQUAL)      s += 2;
    if (f & CAMPAIGN_SIG_SUBJECT_SIMILAR)    s += 1;
    if (f & CAMPAIGN_SIG_BODY_SIMILAR)       s += 2;
    if (f & CAMPAIGN_SIG_SHARED_BRAND)       s += 1;
    return s;
}

/* ------------------------------------------------------------------ */
/* Agrupación (unión de conjuntos)                                     */
/* ------------------------------------------------------------------ */

static size_t find_root(size_t *parent, size_t x)
{
    while (parent[x] != x) {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    return x;
}

static void unite(size_t *parent, size_t a, size_t b)
{
    size_t ra = find_root(parent, a);
    size_t rb = find_root(parent, b);

    if (ra != rb)
        parent[rb] = ra;
}

/* ------------------------------------------------------------------ */
/* API pública                                                         */
/* ------------------------------------------------------------------ */

void campaign_describe(unsigned int signals, char *out, size_t size)
{
    size_t used = 0;

    if (!out || size == 0)
        return;

    out[0] = '\0';
    for (size_t i = 0; i < SIGNAL_COUNT; i++) {
        int n;

        if (!(signals & SIGNAL_NAMES[i].bit))
            continue;
        n = snprintf(out + used, size - used, "%s%s", used ? ", " : "", SIGNAL_NAMES[i].name);
        if (n < 0 || (size_t)n >= size - used)
            break;
        used += (size_t)n;
    }

    if (used == 0)
        snprintf(out, size, "nada en común");
}

int campaign_detect(const EmailMessage *emails, size_t count, CampaignReport *out)
{
    Profile *profiles = NULL;
    PairLink *links = NULL;
    size_t *parent = NULL;
    size_t *comp_size = NULL;
    size_t *cid = NULL;
    size_t link_count = 0;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, sizeof *out);

    if (count == 0)
        return 0;
    if (!emails || count > CAMPAIGN_MAX_EMAILS)
        return -1;
    if (count < 2)
        return 0;

    profiles = calloc(count, sizeof *profiles);
    parent = malloc(count * sizeof *parent);
    comp_size = calloc(count, sizeof *comp_size);
    cid = malloc(count * sizeof *cid);
    links = malloc((count * (count - 1) / 2) * sizeof *links);
    if (!profiles || !parent || !comp_size || !cid || !links)
        goto done;

    for (size_t i = 0; i < count; i++) {
        build_profile(&emails[i], &profiles[i]);
        parent[i] = i;
        cid[i] = NO_CAMPAIGN;
    }

    /* Compara todos los pares y guarda los que superan el puntaje mínimo */
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            unsigned int f = compare_profiles(&emails[i], &profiles[i], &emails[j], &profiles[j]);

            if (pair_score(f) >= CAMPAIGN_MIN_SCORE) {
                links[link_count].a = i;
                links[link_count].b = j;
                links[link_count].flags = f;
                link_count++;
            }
        }
    }

    for (size_t k = 0; k < link_count; k++)
        unite(parent, links[k].a, links[k].b);

    for (size_t i = 0; i < count; i++)
        comp_size[find_root(parent, i)]++;

    /* Crea una campaña por grupo de dos o más correos */
    for (size_t i = 0; i < count; i++) {
        size_t r = find_root(parent, i);
        Campaign *c;

        if (comp_size[r] < 2)
            continue;
        if (cid[r] == NO_CAMPAIGN) {
            if (out->campaign_count >= CAMPAIGN_MAX_EMAILS)
                continue;
            cid[r] = out->campaign_count++;
        }
        c = &out->campaigns[cid[r]];
        if (c->member_count < CAMPAIGN_MAX_MEMBERS)
            c->members[c->member_count++] = i;
    }

    /* Señales de cada campaña: unión de las señales de sus pares */
    for (size_t k = 0; k < link_count; k++) {
        size_t r = find_root(parent, links[k].a);

        if (cid[r] != NO_CAMPAIGN)
            out->campaigns[cid[r]].signals |= links[k].flags;
    }

    for (size_t c = 0; c < out->campaign_count; c++) {
        char desc[256];   /* todas las señales juntas ocupan menos de 200 caracteres */
        Campaign *camp = &out->campaigns[c];

        campaign_describe(camp->signals, desc, sizeof desc);
        snprintf(camp->summary, sizeof camp->summary,
                 "Campaña de %zu correos. Comparten: %s.", camp->member_count, desc);
    }

    rc = 0;

done:
    free(profiles);
    free(parent);
    free(comp_size);
    free(cid);
    free(links);
    return rc;
}
