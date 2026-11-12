#ifndef FINOVRA_CAMPAIGN_DETECTOR_H
#define FINOVRA_CAMPAIGN_DETECTOR_H

#include <stddef.h>

#include "email_analyzer.h"

#define CAMPAIGN_MAX_EMAILS     64
#define CAMPAIGN_MAX_MEMBERS    64
#define CAMPAIGN_MIN_SCORE      3     /* puntaje mínimo para considerar dos correos relacionados */
#define CAMPAIGN_TEXT_LEN       512

/*
 * Señales que hacen que dos correos se relacionen.
 * Cada una aporta un peso al puntaje (ver campaign_detector.c).
 */
typedef enum {
    CAMPAIGN_SIG_SHARED_URL         = 1u << 0,  /* mismo enlace exacto            (3) */
    CAMPAIGN_SIG_SHARED_HOST        = 1u << 1,  /* mismo servidor en un enlace    (2) */
    CAMPAIGN_SIG_SAME_SENDER        = 1u << 2,  /* misma dirección de remitente   (2) */
    CAMPAIGN_SIG_SAME_SENDER_DOMAIN = 1u << 3,  /* mismo dominio de remitente     (1) */
    CAMPAIGN_SIG_SUBJECT_EQUAL      = 1u << 4,  /* asunto igual tras normalizar   (2) */
    CAMPAIGN_SIG_SUBJECT_SIMILAR    = 1u << 5,  /* asunto parecido               (1) */
    CAMPAIGN_SIG_BODY_SIMILAR       = 1u << 6,  /* texto con la mitad de palabras (2) */
    CAMPAIGN_SIG_SHARED_BRAND       = 1u << 7   /* misma marca mencionada         (1) */
} CampaignSignal;

typedef struct {
    size_t members[CAMPAIGN_MAX_MEMBERS];   /* índices en el arreglo de correos de entrada */
    size_t member_count;
    unsigned int signals;                   /* combinación de CampaignSignal */
    char summary[CAMPAIGN_TEXT_LEN];        /* explicación legible */
} Campaign;

typedef struct {
    Campaign campaigns[CAMPAIGN_MAX_EMAILS];
    size_t campaign_count;
} CampaignReport;

/*
 * Agrupa los correos relacionados. Solo devuelve campañas de 2 o más correos.
 * Devuelve 0 si fue exitoso, -1 si los argumentos no son válidos.
 */
int campaign_detect(const EmailMessage *emails, size_t count, CampaignReport *out);

/* Describe en español las señales de una combinación, por ejemplo "enlace idéntico, mismo asunto". */
void campaign_describe(unsigned int signals, char *out, size_t size);

#endif /* FINOVRA_CAMPAIGN_DETECTOR_H */
