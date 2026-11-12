#ifndef FINOVRA_INTEL_H
#define FINOVRA_INTEL_H

#include <stdbool.h>
#include <stddef.h>

#include "url_analyzer.h"

/*
 * Lista local de dominios maliciosos. La mantiene el usuario en un archivo de texto,
 * un dominio por línea. Las líneas que empiezan con '#' son comentarios.
 * No se consulta ningún servicio externo: todo ocurre en el equipo.
 */

#define INTEL_MAX_DOMAINS   2000000 /* límite de seguridad; la memoria crece según la lista */
#define INTEL_DOMAIN_LEN    256

typedef struct Blocklist Blocklist;

Blocklist *intel_blocklist_new(void);
void intel_blocklist_free(Blocklist *bl);

/* Agrega un dominio. Devuelve 0 si se guardó, -1 si está lleno o es inválido. */
int intel_blocklist_add(Blocklist *bl, const char *domain);

/*
 * Carga un archivo. 'loaded' recibe cuántos dominios se agregaron.
 * Devuelve 0 si el archivo se pudo leer, -1 si no existe o no se puede abrir.
 */
int intel_blocklist_load_file(Blocklist *bl, const char *path, size_t *loaded);

size_t intel_blocklist_size(const Blocklist *bl);

/* true si el host es un dominio de la lista o un subdominio de uno de ellos */
bool intel_blocklist_contains_host(const Blocklist *bl, const char *host);

/*
 * Si la URL apunta a un dominio de la lista, agrega un hallazgo de alto riesgo
 * al reporte y recalcula el nivel final. Devuelve 1 si coincidió, 0 si no.
 */
int intel_apply_blocklist(const Blocklist *bl, const char *url, UrlReport *report);

#endif /* FINOVRA_INTEL_H */
