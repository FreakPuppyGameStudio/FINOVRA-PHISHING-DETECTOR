#ifndef FINOVRA_DATABASE_H
#define FINOVRA_DATABASE_H

#include <stdint.h>

#include "campaign_detector.h"
#include "email_analyzer.h"
#include "url_analyzer.h"

typedef struct Database Database;

/* Totales para el panel de resumen */
typedef struct {
    int64_t url_scans;      /* URLs analizadas */
    int64_t emails;         /* correos analizados */
    int64_t email_urls;     /* enlaces guardados de correos */
    int64_t high_risk;     /* URLs y correos con alto riesgo */
    int64_t campaigns;      /* campañas guardadas */
} DbStats;

/*
 * Abre (o crea) la base de datos y prepara las tablas.
 * 'path' puede ser ":memory:" para pruebas. Devuelve 0 si fue exitoso.
 */
int db_open(const char *path, Database **out);

void db_close(Database *db);

/* Último mensaje de error de SQLite, o cadena vacía. */
const char *db_last_error(const Database *db);

/* Guarda el resultado de analizar una URL. */
int db_save_url_scan(Database *db, const char *url, UrlRisk risk,
                     const char *summary, int64_t *out_id);

/*
 * Guarda un correo, su nivel de riesgo y sus enlaces, todo en una transacción.
 * Si algo falla, no se guarda nada.
 */
int db_save_email(Database *db, const EmailMessage *m, UrlRisk risk,
                  const char *summary, int64_t *out_id);

/*
 * Guarda una campaña. 'email_ids' debe tener un id de base de datos por cada
 * correo de la sesión, en el mismo orden que los índices de la campaña.
 */
int db_save_campaign(Database *db, const Campaign *c,
                     const int64_t *email_ids, size_t id_count, int64_t *out_id);

int db_stats(Database *db, DbStats *out);

/*
 * Borra todo el historial: URLs, correos, enlaces de correos y campañas.
 * Es una sola transacción: o se borra todo, o nada.
 */
int db_clear_history(Database *db);

/* Conteos por nivel de riesgo, para las gráficas de porcentajes */
typedef struct {
    int64_t url_low;
    int64_t url_suspicious;
    int64_t url_high;
    int64_t email_low;
    int64_t email_suspicious;
    int64_t email_high;
} DbRiskBreakdown;

int db_risk_breakdown(Database *db, DbRiskBreakdown *out);

/* Texto con los análisis más recientes (URLs y correos), más nuevos primero. */
int db_recent_text(Database *db, size_t limit, char *out, size_t size);

#endif /* FINOVRA_DATABASE_H */
