#ifndef FINOVRA_EMAIL_ANALYZER_H
#define FINOVRA_EMAIL_ANALYZER_H

#include <stdbool.h>
#include <stddef.h>

#include "url_analyzer.h"

#define EMAIL_FIELD_LEN     512
#define EMAIL_AUTH_LEN      1024
#define EMAIL_URL_LEN       512
#define EMAIL_MAX_URLS      32
#define EMAIL_MAX_ATTACH    16
#define EMAIL_MAX_FINDINGS  32
#define EMAIL_MAX_BODY      (1024 * 1024)

/* Adjunto: solo se leen sus metadatos. Nunca se decodifica ni se abre. */
typedef struct {
    char name[256];
    char content_type[128];
    size_t size;                /* tamaño del bloque codificado en el mensaje */
} EmailAttachment;

typedef struct {
    char from[EMAIL_FIELD_LEN];
    char reply_to[EMAIL_FIELD_LEN];
    char return_path[EMAIL_FIELD_LEN];
    char subject[EMAIL_FIELD_LEN];
    char date[128];
    char message_id[EMAIL_FIELD_LEN];
    char auth_results[EMAIL_AUTH_LEN];  /* cabecera Authentication-Results tal como viene */
    bool has_auth_results;

    char *body;                 /* texto decodificado de las partes de texto; liberar con email_free() */
    size_t body_len;

    char urls[EMAIL_MAX_URLS][EMAIL_URL_LEN];
    size_t url_count;

    EmailAttachment attachments[EMAIL_MAX_ATTACH];
    size_t attachment_count;
} EmailMessage;

typedef struct {
    UrlFinding findings[EMAIL_MAX_FINDINGS];
    size_t finding_count;
    UrlRisk overall;
} EmailReport;

/* Parsea un mensaje .eml en memoria. Devuelve 0 si fue exitoso. */
int email_parse(const char *raw, size_t raw_len, EmailMessage *out);

/* Libera la memoria del cuerpo. */
void email_free(EmailMessage *msg);

/* Genera hallazgos explicables. Devuelve 0 si fue exitoso. */
int email_analyze(const EmailMessage *msg, EmailReport *report);

#endif /* FINOVRA_EMAIL_ANALYZER_H */
