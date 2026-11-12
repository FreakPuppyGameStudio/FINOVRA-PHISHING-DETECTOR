#ifndef FINOVRA_URL_ANALYZER_H
#define FINOVRA_URL_ANALYZER_H

#include <stdbool.h>
#include <stddef.h>

#define URL_MAX_INPUT      2048
#define URL_MAX_HOST       256
#define URL_MAX_PATH       1024
#define URL_MAX_USERINFO   256
#define URL_MAX_FINDINGS   16
#define URL_TEXT_LEN       768
#define URL_INDICATOR_LEN  64

/* Clasificación final y por hallazgo */
typedef enum {
    URL_RISK_LOW = 0,
    URL_RISK_SUSPICIOUS,
    URL_RISK_HIGH
} UrlRisk;

typedef enum {
    URL_CONFIDENCE_LOW = 0,
    URL_CONFIDENCE_MEDIUM,
    URL_CONFIDENCE_HIGH
} UrlConfidence;

/* Un indicador detectado, con su explicación y evidencia */
typedef struct {
    char indicator[URL_INDICATOR_LEN];
    UrlRisk severity;
    UrlConfidence confidence;
    char reason[URL_TEXT_LEN];
    char evidence[URL_TEXT_LEN];
} UrlFinding;

/* Partes de la URL, ya separadas */
typedef struct {
    char scheme[16];
    bool has_userinfo;
    char userinfo[URL_MAX_USERINFO];
    char host[URL_MAX_HOST];
    int port;                       /* -1 si la URL no trae puerto */
    char path[URL_MAX_PATH];
} UrlParts;

/* Resultado completo del análisis de una URL */
typedef struct {
    UrlParts parts;
    UrlFinding findings[URL_MAX_FINDINGS];
    size_t finding_count;
    UrlRisk overall;
} UrlReport;

/* Separa la URL en partes. Devuelve false si la URL no es válida. */
bool url_parse(const char *input, UrlParts *out);

/* Analiza la URL y llena el reporte. Devuelve 0 si fue exitoso, -1 si no se pudo analizar. */
int url_analyze(const char *input, UrlReport *report);

/* Distancia de Levenshtein entre dos cadenas (para detectar imitaciones de marcas). */
int url_levenshtein(const char *a, const char *b);

/* Nombre legible del nivel de riesgo, en español. */
const char *url_risk_name(UrlRisk risk);

/* Devuelve la marca conocida igual a 'word' (en minúsculas), o NULL si no es una marca. */
const char *url_known_brand(const char *word);

#endif /* FINOVRA_URL_ANALYZER_H */
