#ifndef FINOVRA_DOMAIN_HEURISTICS_H
#define FINOVRA_DOMAIN_HEURISTICS_H

#include "url_analyzer.h"

/*
 * Características del nombre del dominio, sin listas externas:
 *   - nombre con apariencia aleatoria (entropía alta), que suele venir de generadores de dominios
 *   - muchos dígitos, o nombres muy largos
 *   - secuencias largas de consonantes
 *   - palabras de acceso o presión dentro del nombre (login, verify, secure, cuenta...)
 *   - dominios de registro barato (.xyz, .top, .tk...)
 *
 * Solo se mira el nombre principal (la etiqueta que identifica al dueño del dominio),
 * no los subdominios: así "secure-login.ejemplo.com" no acumula sospechas por sus
 * subdominios. Las reglas son débiles por sí solas; se combinan con la regla de riesgo.
 *
 * Añade hallazgos a 'report' pero no recalcula el nivel final.
 */
void domain_characteristics(const char *host, UrlReport *report);

#endif /* FINOVRA_DOMAIN_HEURISTICS_H */
