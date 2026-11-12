#ifndef FINOVRA_RISK_ENGINE_H
#define FINOVRA_RISK_ENGINE_H

#include <stddef.h>

#include "url_analyzer.h"

/*
 * Motor de riesgo: una sola regla de agregación para URLs, correos y,
 * en el futuro, campañas. Los analizadores le pasan sus hallazgos y
 * el motor decide el nivel final.
 *
 * Regla:
 *   - Cualquier hallazgo de alto riesgo        -> Alto riesgo
 *   - Dos o más hallazgos sospechosos         -> Alto riesgo
 *   - Un sospechoso, o dos o más débiles       -> Sospechosa
 *   - En otro caso                             -> Bajo riesgo
 *
 * Así un solo indicador débil nunca marca una URL o un correo como sospechoso.
 */

typedef struct {
    size_t high;
    size_t suspicious;
    size_t low;
} RiskCounts;

/* Cuenta los hallazgos por nivel de severidad. */
void risk_count(const UrlFinding *findings, size_t count, RiskCounts *out);

/* Nivel final según la regla anterior. */
UrlRisk risk_aggregate(const UrlFinding *findings, size_t count);

/*
 * Escribe un resumen explicable en 'out', por ejemplo:
 *   "Nivel final: Sospechosa (altos: 0, sospechosos: 1, débiles: 2). Motivo: ..."
 * Devuelve 0 si fue exitoso, -1 si el buffer es nulo.
 */
int risk_explain(const UrlFinding *findings, size_t count, char *out, size_t size);

#endif /* FINOVRA_RISK_ENGINE_H */
