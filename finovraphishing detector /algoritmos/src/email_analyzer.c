#include "email_analyzer.h"
#include "risk_engine.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PART_DEPTH  3
#define HDR_NAME_LEN    64
#define HDR_VALUE_LEN   2048

/* Palabras clave: español e inglés. Son pistas, no prueba de phishing. */
static const char *const URGENCY_WORDS[] = {
    "urgente", "inmediatamente", "suspendid", "verifica tu cuenta",
    "de inmediato", "urgent", "immediately", "suspended",
    "verify your account", "act now", "within 24 hours"
};
#define URGENCY_COUNT (sizeof URGENCY_WORDS / sizeof URGENCY_WORDS[0])

static const char *const CREDENTIAL_WORDS[] = {
    "contraseña", "contrasena", "password", "clave de acceso",
    "número de tarjeta", "numero de tarjeta", "card number", "cvv",
    "datos bancarios", "confirma tus datos", "confirm your details",
    "ingresa tus credenciales", "verify your identity"
};
#define CREDENTIAL_COUNT (sizeof CREDENTIAL_WORDS / sizeof CREDENTIAL_WORDS[0])

static const char *const DANGEROUS_EXTENSIONS[] = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
    ".lnk", ".iso", ".msi", ".hta", ".docm", ".xlsm"
};
#define DANGEROUS_EXT_COUNT (sizeof DANGEROUS_EXTENSIONS / sizeof DANGEROUS_EXTENSIONS[0])

/* Cabeceras relevantes de una parte del mensaje */
typedef struct {
    char from[EMAIL_FIELD_LEN];
    char reply_to[EMAIL_FIELD_LEN];
    char return_path[EMAIL_FIELD_LEN];
    char subject[EMAIL_FIELD_LEN];
    char date[128];
    char message_id[EMAIL_FIELD_LEN];
    char auth_results[EMAIL_AUTH_LEN];
    bool has_auth;
    char content_type[128];
    char boundary[128];
    char encoding[32];
    char disposition[32];
    char filename[256];
} HeaderBlock;

/* Buffer creciente para el texto decodificado */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} TextBuf;

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

/* Copia n caracteres quitando espacios al inicio y al final. */
static void copy_trimmed(char *dst, size_t size, const char *src, size_t n)
{
    if (size == 0)
        return;
    while (n > 0 && isspace((unsigned char)*src)) {
        src++;
        n--;
    }
    while (n > 0 && isspace((unsigned char)src[n - 1]))
        n--;
    if (n >= size)
        n = size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void to_lower_inplace(char *s)
{
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

static void remove_char(char *s, char c)
{
    char *w = s;

    for (char *r = s; *r; r++) {
        if (*r != c)
            *w++ = *r;
    }
    *w = '\0';
}

/*
 * Busca un parámetro como boundary="x" o filename=x dentro de una cabecera.
 * "name" no coincide dentro de "filename" porque debe ir al inicio o tras ';' o espacio.
 */
static bool get_param(const char *value, const char *key, char *out, size_t size)
{
    char lower[HDR_VALUE_LEN];
    size_t klen = strlen(key);
    const char *p;

    copy_str(lower, sizeof lower, value);
    to_lower_inplace(lower);

    p = lower;
    while ((p = strstr(p, key)) != NULL) {
        bool at_start = (p == lower) || p[-1] == ';' || p[-1] == ' ' || p[-1] == '\t';

        if (at_start && p[klen] == '=') {
            const char *v = value + (p - lower) + klen + 1;
            size_t n = 0;

            if (*v == '"') {
                v++;
                while (v[n] && v[n] != '"')
                    n++;
            } else {
                while (v[n] && v[n] != ';' && !isspace((unsigned char)v[n]))
                    n++;
            }
            copy_str(out, size, "");
            if (n >= size)
                n = size - 1;
            memcpy(out, v, n);
            out[n] = '\0';
            return true;
        }
        p += klen;
    }
    return false;
}

/* Separa "Nombre <correo@dominio>" en nombre y correo (en minúsculas). */
static void address_parts(const char *value, char *addr, size_t asize, char *name, size_t nsize)
{
    const char *lt = strchr(value, '<');
    const char *gt = lt ? strchr(lt, '>') : NULL;

    if (lt && gt) {
        copy_trimmed(addr, asize, lt + 1, (size_t)(gt - lt - 1));
        copy_trimmed(name, nsize, value, (size_t)(lt - value));
        remove_char(name, '"');
    } else {
        copy_trimmed(addr, asize, value, strlen(value));
        name[0] = '\0';
    }
    to_lower_inplace(addr);
}

static void domain_of(const char *addr, char *dom, size_t size)
{
    const char *at = strrchr(addr, '@');

    if (at)
        copy_str(dom, size, at + 1);
    else
        dom[0] = '\0';
}

/* true si alguna etiqueta del dominio es exactamente 'label' (paypal.com contiene "paypal") */
static bool domain_has_label(const char *domain, const char *label)
{
    const char *p = domain;
    size_t ll = strlen(label);

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t n = dot ? (size_t)(dot - p) : strlen(p);

        if (n == ll && strncmp(p, label, n) == 0)
            return true;
        if (!dot)
            break;
        p = dot + 1;
    }
    return false;
}

static size_t count_matches(const char *lower, const char *const *words, size_t n)
{
    size_t hits = 0;

    for (size_t i = 0; i < n; i++) {
        if (strstr(lower, words[i]) != NULL)
            hits++;
    }
    return hits;
}

/* ------------------------------------------------------------------ */
/* Decodificación                                                      */
/* ------------------------------------------------------------------ */

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    return 10 + (tolower((unsigned char)c) - 'a');
}

/* Quoted-printable: =XX y saltos suaves "=" al final de línea */
static char *decode_qp(const char *src, size_t len, size_t *out_len)
{
    char *out = malloc(len + 1);
    size_t o = 0;

    if (!out)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        if (src[i] == '=') {
            if (i + 1 < len && (src[i + 1] == '\n' || src[i + 1] == '\r')) {
                i++;
                if (src[i] == '\r' && i + 1 < len && src[i + 1] == '\n')
                    i++;
                continue;
            }
            if (i + 2 < len && isxdigit((unsigned char)src[i + 1]) && isxdigit((unsigned char)src[i + 2])) {
                out[o++] = (char)((hexval(src[i + 1]) << 4) | hexval(src[i + 2]));
                i += 2;
                continue;
            }
        }
        out[o++] = src[i];
    }
    out[o] = '\0';
    *out_len = o;
    return out;
}

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* Base64: ignora espacios, saltos de línea y '=' */
static char *decode_b64(const char *src, size_t len, size_t *out_len)
{
    char *out = malloc(len / 4 * 3 + 4);
    size_t o = 0;
    unsigned int acc = 0;
    int bits = 0;

    if (!out)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        int v = b64_value((unsigned char)src[i]);

        if (v < 0)
            continue;
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (char)((acc >> bits) & 0xFF);
        }
    }
    out[o] = '\0';
    *out_len = o;
    return out;
}

static char *decode_part(const char *src, size_t len, const char *encoding, size_t *out_len)
{
    if (strcmp(encoding, "quoted-printable") == 0)
        return decode_qp(src, len, out_len);
    if (strcmp(encoding, "base64") == 0)
        return decode_b64(src, len, out_len);

    {
        char *copy = malloc(len + 1);

        if (!copy)
            return NULL;
        memcpy(copy, src, len);
        copy[len] = '\0';
        *out_len = len;
        return copy;
    }
}

/* ------------------------------------------------------------------ */
/* Buffer de texto y URLs                                              */
/* ------------------------------------------------------------------ */

static bool buf_append(TextBuf *b, const char *s, size_t n)
{
    size_t need = b->len + n + 1;

    if (need > EMAIL_MAX_BODY)
        return false;
    if (need > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        char *nd;

        while (nc < need)
            nc *= 2;
        nd = realloc(b->data, nc);
        if (!nd)
            return false;
        b->data = nd;
        b->cap = nc;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return true;
}

static void add_url(EmailMessage *msg, const char *s, size_t n)
{
    char tmp[EMAIL_URL_LEN];

    if (msg->url_count >= EMAIL_MAX_URLS || n == 0 || n >= EMAIL_URL_LEN)
        return;

    memcpy(tmp, s, n);
    tmp[n] = '\0';

    /* Quitar puntuación final que no forma parte de la URL */
    while (n > 0 && strchr(".,;:!?)]}", tmp[n - 1]) != NULL)
        tmp[--n] = '\0';
    if (n < 8)
        return;

    for (size_t i = 0; i < msg->url_count; i++) {
        if (strcmp(msg->urls[i], tmp) == 0)
            return;
    }
    copy_str(msg->urls[msg->url_count++], EMAIL_URL_LEN, tmp);
}

static void extract_urls(EmailMessage *msg, const char *text, size_t len)
{
    const char *p = text;
    const char *end = text + len;

    while (p < end) {
        bool is_url = ((size_t)(end - p) >= 8 && strncmp(p, "https://", 8) == 0) ||
                      ((size_t)(end - p) >= 7 && strncmp(p, "http://", 7) == 0);

        if (is_url) {
            const char *q = p;

            while (q < end && *q != '\0' && strchr(" \t\r\n<>\"'", *q) == NULL)
                q++;
            add_url(msg, p, (size_t)(q - p));
            p = q;
        } else {
            p++;
        }
    }
}

static void add_attachment(EmailMessage *msg, const char *name, const char *content_type, size_t size)
{
    EmailAttachment *a;

    if (msg->attachment_count >= EMAIL_MAX_ATTACH)
        return;
    a = &msg->attachments[msg->attachment_count++];
    copy_str(a->name, sizeof a->name, name);
    copy_str(a->content_type, sizeof a->content_type, content_type);
    a->size = size;
}

/* ------------------------------------------------------------------ */
/* Parser de cabeceras y partes                                        */
/* ------------------------------------------------------------------ */

static void apply_header(HeaderBlock *hb, const char *name, const char *value)
{
    if (strcmp(name, "from") == 0) {
        copy_str(hb->from, sizeof hb->from, value);
    } else if (strcmp(name, "reply-to") == 0) {
        copy_str(hb->reply_to, sizeof hb->reply_to, value);
    } else if (strcmp(name, "return-path") == 0) {
        copy_str(hb->return_path, sizeof hb->return_path, value);
    } else if (strcmp(name, "subject") == 0) {
        copy_str(hb->subject, sizeof hb->subject, value);
    } else if (strcmp(name, "date") == 0) {
        copy_str(hb->date, sizeof hb->date, value);
    } else if (strcmp(name, "message-id") == 0) {
        copy_str(hb->message_id, sizeof hb->message_id, value);
    } else if (strcmp(name, "authentication-results") == 0) {
        copy_str(hb->auth_results, sizeof hb->auth_results, value);
        hb->has_auth = true;
    } else if (strcmp(name, "content-type") == 0) {
        copy_str(hb->content_type, sizeof hb->content_type, value);
        to_lower_inplace(hb->content_type);
        get_param(value, "boundary", hb->boundary, sizeof hb->boundary);
        if (hb->filename[0] == '\0')
            get_param(value, "name", hb->filename, sizeof hb->filename);
    } else if (strcmp(name, "content-transfer-encoding") == 0) {
        copy_trimmed(hb->encoding, sizeof hb->encoding, value, strlen(value));
        to_lower_inplace(hb->encoding);
    } else if (strcmp(name, "content-disposition") == 0) {
        const char *semi = strchr(value, ';');
        size_t n = semi ? (size_t)(semi - value) : strlen(value);

        copy_trimmed(hb->disposition, sizeof hb->disposition, value, n);
        to_lower_inplace(hb->disposition);
        get_param(value, "filename", hb->filename, sizeof hb->filename);
    }
}

/* Lee las cabeceras de [start, end) uniendo las líneas que empiezan con espacio o tab */
static void parse_header_block(const char *start, const char *end, HeaderBlock *hb)
{
    char name[HDR_NAME_LEN] = "";
    char value[HDR_VALUE_LEN] = "";
    bool have = false;
    const char *p = start;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;
        size_t ll = (size_t)(line_end - p);

        if (ll > 0 && p[ll - 1] == '\r')
            ll--;

        if (ll > 0 && (p[0] == ' ' || p[0] == '\t')) {
            if (have) {
                size_t vl = strlen(value);

                if (vl + 1 < sizeof value) {
                    value[vl] = ' ';
                    copy_trimmed(value + vl + 1, sizeof value - vl - 1, p, ll);
                }
            }
        } else {
            const char *colon;

            if (have) {
                to_lower_inplace(name);
                apply_header(hb, name, value);
            }
            have = false;

            colon = memchr(p, ':', ll);
            if (colon) {
                size_t nlen = (size_t)(colon - p);

                copy_trimmed(name, sizeof name, p, nlen);
                copy_trimmed(value, sizeof value, colon + 1, ll - nlen - 1);
                have = true;
            }
        }
        p = nl ? nl + 1 : end;
    }

    if (have) {
        to_lower_inplace(name);
        apply_header(hb, name, value);
    }
}

/* Devuelve el final de las cabeceras (línea vacía) y deja en *body el inicio del cuerpo */
static const char *find_header_end(const char *start, const char *end, const char **body)
{
    const char *p = start;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;
        size_t ll = (size_t)(line_end - p);

        if (ll > 0 && p[ll - 1] == '\r')
            ll--;
        if (ll == 0) {
            *body = nl ? nl + 1 : end;
            return p;
        }
        p = nl ? nl + 1 : end;
    }
    *body = end;
    return end;
}

static void process_leaf(const HeaderBlock *hb, const char *body, const char *end,
                         EmailMessage *msg, TextBuf *text)
{
    bool is_text = hb->content_type[0] == '\0' || strncmp(hb->content_type, "text/", 5) == 0;
    bool attachment = !is_text || hb->filename[0] != '\0' || strcmp(hb->disposition, "attachment") == 0;
    size_t raw_len = (size_t)(end - body);

    if (attachment) {
        add_attachment(msg,
                       hb->filename[0] ? hb->filename : "(sin nombre)",
                       hb->content_type[0] ? hb->content_type : "application/octet-stream",
                       raw_len);
        return;
    }

    {
        size_t dl = 0;
        char *decoded = decode_part(body, raw_len, hb->encoding, &dl);

        if (!decoded)
            return;
        buf_append(text, decoded, dl);
        buf_append(text, "\n", 1);
        extract_urls(msg, decoded, dl);
        free(decoded);
    }
}

static void parse_entity(const char *body, const char *end, const HeaderBlock *hb,
                         EmailMessage *msg, TextBuf *text, int depth);

static void parse_part(const char *start, const char *end, EmailMessage *msg, TextBuf *text, int depth)
{
    HeaderBlock hb;
    const char *body = NULL;
    const char *hend;

    if (depth > MAX_PART_DEPTH)
        return;

    memset(&hb, 0, sizeof hb);
    hend = find_header_end(start, end, &body);
    parse_header_block(start, hend, &hb);
    parse_entity(body, end, &hb, msg, text, depth);
}

/* Delimitador "--boundary" al inicio de una línea */
static bool is_delimiter(const char *line, const char *line_end, const char *boundary, size_t bl)
{
    if ((size_t)(line_end - line) < bl + 2)
        return false;
    return line[0] == '-' && line[1] == '-' && memcmp(line + 2, boundary, bl) == 0;
}

/* Delimitador de cierre "--boundary--" */
static bool is_closing(const char *line, const char *line_end, size_t bl)
{
    return (size_t)(line_end - line) >= bl + 4 && line[bl + 2] == '-' && line[bl + 3] == '-';
}

static void parse_multipart(const char *body, const char *end, const char *boundary,
                            EmailMessage *msg, TextBuf *text, int depth)
{
    size_t bl = strlen(boundary);
    const char *part_start = NULL;
    const char *p = body;

    if (bl == 0)
        return;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;

        if (is_delimiter(p, line_end, boundary, bl)) {
            if (part_start)
                parse_part(part_start, p, msg, text, depth + 1);
            part_start = nl ? nl + 1 : end;
            if (is_closing(p, line_end, bl))
                return;
        }
        p = nl ? nl + 1 : end;
    }

    /* Sin delimitador de cierre: procesa lo que quede */
    if (part_start && part_start < end)
        parse_part(part_start, end, msg, text, depth + 1);
}

static void parse_entity(const char *body, const char *end, const HeaderBlock *hb,
                         EmailMessage *msg, TextBuf *text, int depth)
{
    if (strncmp(hb->content_type, "multipart/", 10) == 0)
        parse_multipart(body, end, hb->boundary, msg, text, depth);
    else
        process_leaf(hb, body, end, msg, text);
}

int email_parse(const char *raw, size_t raw_len, EmailMessage *out)
{
    const char *end;
    const char *body = NULL;
    const char *hend;
    HeaderBlock hb;
    TextBuf text = {NULL, 0, 0};

    if (!raw || !out)
        return -1;

    memset(out, 0, sizeof *out);
    memset(&hb, 0, sizeof hb);

    end = raw + raw_len;
    hend = find_header_end(raw, end, &body);
    parse_header_block(raw, hend, &hb);

    copy_str(out->from, sizeof out->from, hb.from);
    copy_str(out->reply_to, sizeof out->reply_to, hb.reply_to);
    copy_str(out->return_path, sizeof out->return_path, hb.return_path);
    copy_str(out->subject, sizeof out->subject, hb.subject);
    copy_str(out->date, sizeof out->date, hb.date);
    copy_str(out->message_id, sizeof out->message_id, hb.message_id);
    copy_str(out->auth_results, sizeof out->auth_results, hb.auth_results);
    out->has_auth_results = hb.has_auth;

    parse_entity(body, end, &hb, out, &text, 0);

    if (!text.data) {
        text.data = calloc(1, 1);
        if (!text.data)
            return -1;
    }
    out->body = text.data;
    out->body_len = text.len;
    return 0;
}

void email_free(EmailMessage *msg)
{
    if (!msg)
        return;
    free(msg->body);
    msg->body = NULL;
    msg->body_len = 0;
}

/* ------------------------------------------------------------------ */
/* Hallazgos                                                           */
/* ------------------------------------------------------------------ */

static void add_finding(EmailReport *r, const char *indicator, UrlRisk severity,
                        UrlConfidence confidence, const char *reason, const char *evidence)
{
    UrlFinding *f;

    if (r->finding_count >= EMAIL_MAX_FINDINGS)
        return;

    f = &r->findings[r->finding_count++];
    copy_str(f->indicator, sizeof f->indicator, indicator);
    f->severity = severity;
    f->confidence = confidence;
    copy_str(f->reason, sizeof f->reason, reason);
    copy_str(f->evidence, sizeof f->evidence, evidence);
}

/* Marca conocida dentro del nombre visible ("PayPal Soporte") que no coincide con el dominio */
static void check_display_name_brand(const char *name, const char *from_dom, EmailReport *r)
{
    char lower[EMAIL_FIELD_LEN];
    size_t i = 0;
    char text[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];

    copy_str(lower, sizeof lower, name);
    to_lower_inplace(lower);

    while (lower[i]) {
        size_t start = i;
        size_t wl;

        while (lower[i] && isalpha((unsigned char)lower[i]))
            i++;
        wl = i - start;

        if (wl >= 5 && wl < 64) {
            char word[64];
            const char *brand;

            memcpy(word, lower + start, wl);
            word[wl] = '\0';
            brand = url_known_brand(word);

            if (brand && !domain_has_label(from_dom, brand)) {
                snprintf(text, sizeof text,
                         "El nombre visible dice '%s', pero el correo sale de '%s'.", brand, from_dom);
                snprintf(evidence, sizeof evidence, "nombre='%s', dominio='%s'", name, from_dom);
                add_finding(r, "marca_en_nombre_remitente", URL_RISK_SUSPICIOUS,
                            URL_CONFIDENCE_HIGH, text, evidence);
                return;
            }
        }
        if (lower[i])
            i++;
    }
}

static void check_sender(const EmailMessage *msg, EmailReport *r)
{
    char from_addr[EMAIL_FIELD_LEN];
    char from_name[EMAIL_FIELD_LEN];
    char from_dom[EMAIL_FIELD_LEN];
    char other_addr[EMAIL_FIELD_LEN];
    char other_name[EMAIL_FIELD_LEN];
    char other_dom[EMAIL_FIELD_LEN];
    char text[URL_TEXT_LEN];
    char evidence[2 * EMAIL_FIELD_LEN + 64];

    address_parts(msg->from, from_addr, sizeof from_addr, from_name, sizeof from_name);
    domain_of(from_addr, from_dom, sizeof from_dom);
    if (from_dom[0] == '\0')
        return;

    if (msg->reply_to[0]) {
        address_parts(msg->reply_to, other_addr, sizeof other_addr, other_name, sizeof other_name);
        domain_of(other_addr, other_dom, sizeof other_dom);
        if (other_dom[0] && strcmp(other_dom, from_dom) != 0) {
            snprintf(text, sizeof text,
                     "La respuesta va a un dominio distinto al del remitente.");
            snprintf(evidence, sizeof evidence, "from='%s', reply-to='%s'", from_dom, other_dom);
            add_finding(r, "reply_to_distinto", URL_RISK_LOW, URL_CONFIDENCE_MEDIUM, text, evidence);
        }
    }

    if (msg->return_path[0]) {
        address_parts(msg->return_path, other_addr, sizeof other_addr, other_name, sizeof other_name);
        domain_of(other_addr, other_dom, sizeof other_dom);
        if (other_dom[0] && strcmp(other_dom, from_dom) != 0) {
            snprintf(text, sizeof text,
                     "El servidor de rebote es de un dominio distinto al del remitente.");
            snprintf(evidence, sizeof evidence, "from='%s', return-path='%s'", from_dom, other_dom);
            add_finding(r, "return_path_distinto", URL_RISK_LOW, URL_CONFIDENCE_MEDIUM, text, evidence);
        }
    }

    check_display_name_brand(from_name, from_dom, r);
}

/* Valor de un mecanismo en Authentication-Results: "spf=pass", "dmarc=fail", etc. */
static bool auth_value(const char *auth_lower, const char *key, char *out, size_t size)
{
    const char *p = strstr(auth_lower, key);
    size_t n = 0;

    if (!p)
        return false;
    p += strlen(key);
    while (p[n] && p[n] != ';' && !isspace((unsigned char)p[n]) && p[n] != '(')
        n++;
    copy_str(out, size, "");
    if (n >= size)
        n = size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static void check_authentication(const EmailMessage *msg, EmailReport *r)
{
    char lower[EMAIL_AUTH_LEN];
    char spf[32];
    char dkim[32];
    char dmarc[32];
    char text[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];

    if (!msg->has_auth_results) {
        snprintf(text, sizeof text,
                 "No hay resultados de autenticación (SPF, DKIM, DMARC) en las cabeceras. "
                 "Esto no prueba nada por sí solo.");
        add_finding(r, "sin_autenticacion", URL_RISK_LOW, URL_CONFIDENCE_LOW, text, "sin Authentication-Results");
        return;
    }

    copy_str(lower, sizeof lower, msg->auth_results);
    to_lower_inplace(lower);
    spf[0] = dkim[0] = dmarc[0] = '\0';
    auth_value(lower, "spf=", spf, sizeof spf);
    auth_value(lower, "dkim=", dkim, sizeof dkim);
    auth_value(lower, "dmarc=", dmarc, sizeof dmarc);

    /* Según lo que dice la cabecera del servidor; no verificamos criptográficamente */
    if (strcmp(dmarc, "fail") == 0) {
        snprintf(text, sizeof text,
                 "Las cabeceras indican que DMARC falló. Según el servidor, el correo no es auténtico.");
        snprintf(evidence, sizeof evidence, "dmarc=%s", dmarc);
        add_finding(r, "dmarc_fallido", URL_RISK_SUSPICIOUS, URL_CONFIDENCE_HIGH, text, evidence);
    }
    if (strcmp(spf, "fail") == 0) {
        snprintf(text, sizeof text,
                 "Las cabeceras indican que SPF falló: el servidor que envió no está autorizado por el dominio.");
        snprintf(evidence, sizeof evidence, "spf=%s", spf);
        add_finding(r, "spf_fallido", URL_RISK_LOW, URL_CONFIDENCE_MEDIUM, text, evidence);
    }
    if (strcmp(dkim, "fail") == 0) {
        snprintf(text, sizeof text,
                 "Las cabeceras indican que la firma DKIM falló.");
        snprintf(evidence, sizeof evidence, "dkim=%s", dkim);
        add_finding(r, "dkim_fallido", URL_RISK_LOW, URL_CONFIDENCE_MEDIUM, text, evidence);
    }
}

/* Revisa cada enlace con el analizador de URLs y reporta el peor */
static UrlRisk check_links(const EmailMessage *msg, EmailReport *r)
{
    UrlRisk worst = URL_RISK_LOW;
    size_t worst_idx = 0;
    bool have = false;
    UrlReport worst_rep;

    for (size_t i = 0; i < msg->url_count; i++) {
        UrlReport ur;

        if (url_analyze(msg->urls[i], &ur) != 0)
            continue;
        if (!have || ur.overall > worst) {
            worst = ur.overall;
            worst_idx = i;
            worst_rep = ur;
            have = true;
        }
    }

    if (have && worst >= URL_RISK_SUSPICIOUS) {
        char text[2 * URL_TEXT_LEN];
        char evidence[URL_TEXT_LEN];

        if (worst_rep.finding_count > 0)
            snprintf(text, sizeof text, "Un enlace del mensaje tiene indicadores: %s",
                     worst_rep.findings[0].reason);
        else
            snprintf(text, sizeof text, "Un enlace del mensaje tiene indicadores de riesgo.");
        snprintf(evidence, sizeof evidence, "enlace='%s'", msg->urls[worst_idx]);
        add_finding(r, "enlace_sospechoso", worst, URL_CONFIDENCE_MEDIUM, text, evidence);
    }
    return worst;
}

static void check_urgency(const char *lower, EmailReport *r)
{
    size_t hits = count_matches(lower, URGENCY_WORDS, URGENCY_COUNT);
    char text[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];

    if (hits == 0)
        return;

    snprintf(text, sizeof text,
             "El mensaje usa lenguaje de urgencia o presión (%zu palabra(s) típicas).", hits);
    snprintf(evidence, sizeof evidence, "coincidencias=%zu", hits);
    add_finding(r, "lenguaje_urgente",
                hits >= 2 ? URL_RISK_SUSPICIOUS : URL_RISK_LOW,
                URL_CONFIDENCE_MEDIUM, text, evidence);
}

/* Pedir datos sensibles es normal en algunos correos; se vuelve sospechoso si hay enlaces */
static void check_credentials(const char *lower, UrlRisk link_risk, size_t url_count, EmailReport *r)
{
    size_t hits = count_matches(lower, CREDENTIAL_WORDS, CREDENTIAL_COUNT);
    UrlRisk sev = URL_RISK_LOW;
    char text[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];

    if (hits == 0)
        return;

    if (link_risk == URL_RISK_HIGH)
        sev = URL_RISK_HIGH;
    else if (url_count > 0)
        sev = URL_RISK_SUSPICIOUS;

    snprintf(text, sizeof text, "El mensaje pide datos sensibles (contraseña, tarjeta o similares).");
    snprintf(evidence, sizeof evidence, "coincidencias=%zu, enlaces=%zu", hits, url_count);
    add_finding(r, "solicita_credenciales", sev, URL_CONFIDENCE_MEDIUM, text, evidence);
}

static void check_attachments(const EmailMessage *msg, EmailReport *r)
{
    for (size_t i = 0; i < msg->attachment_count; i++) {
        const EmailAttachment *a = &msg->attachments[i];
        char lower[256];
        size_t nl;
        size_t dots = 0;
        bool dangerous = false;
        char text[URL_TEXT_LEN];
        char evidence[URL_TEXT_LEN];

        copy_str(lower, sizeof lower, a->name);
        to_lower_inplace(lower);
        nl = strlen(lower);

        for (size_t e = 0; e < DANGEROUS_EXT_COUNT; e++) {
            size_t el = strlen(DANGEROUS_EXTENSIONS[e]);

            if (nl > el && strcmp(lower + nl - el, DANGEROUS_EXTENSIONS[e]) == 0) {
                dangerous = true;
                break;
            }
        }
        if (!dangerous)
            continue;

        for (const char *c = lower; *c; c++) {
            if (*c == '.')
                dots++;
        }

        snprintf(evidence, sizeof evidence, "archivo='%s', tipo=%s", a->name, a->content_type);
        if (dots >= 2) {
            snprintf(text, sizeof text,
                     "Adjunto ejecutable con doble extensión, usada para disfrazar el tipo de archivo.");
            add_finding(r, "adjunto_doble_extension", URL_RISK_HIGH, URL_CONFIDENCE_HIGH, text, evidence);
        } else {
            snprintf(text, sizeof text,
                     "Adjunto con extensión ejecutable. No se abrió ni se ejecutó.");
            add_finding(r, "adjunto_ejecutable", URL_RISK_SUSPICIOUS, URL_CONFIDENCE_HIGH, text, evidence);
        }
    }
}

/* Misma regla que para URLs: un débil no basta; tres sospechosos o cualquier alto dan riesgo alto. */
static UrlRisk compute_overall(const EmailReport *r)
{
    return risk_aggregate(r->findings, r->finding_count);
}

int email_analyze(const EmailMessage *msg, EmailReport *report)
{
    char *lower_body;
    UrlRisk link_risk;

    if (!msg || !report)
        return -1;

    memset(report, 0, sizeof *report);

    check_sender(msg, report);
    check_authentication(msg, report);
    link_risk = check_links(msg, report);
    check_attachments(msg, report);

    /* Palabras clave sobre una copia en minúsculas del cuerpo */
    lower_body = malloc(msg->body_len + 1);
    if (!lower_body)
        return -1;
    memcpy(lower_body, msg->body, msg->body_len + 1);
    to_lower_inplace(lower_body);

    check_urgency(lower_body, report);
    check_credentials(lower_body, link_risk, msg->url_count, report);

    free(lower_body);

    report->overall = compute_overall(report);
    return 0;
}
