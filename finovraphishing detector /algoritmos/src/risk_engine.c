#include "risk_engine.h"

#include <stdio.h>
#include <string.h>

void risk_count(const UrlFinding *findings, size_t count, RiskCounts *out)
{
    if (!out)
        return;

    out->high = 0;
    out->suspicious = 0;
    out->low = 0;

    if (!findings)
        return;

    for (size_t i = 0; i < count; i++) {
        switch (findings[i].severity) {
        case URL_RISK_HIGH:
            out->high++;
            break;
        case URL_RISK_SUSPICIOUS:
            out->suspicious++;
            break;
        case URL_RISK_LOW:
            out->low++;
            break;
        }
    }
}

UrlRisk risk_aggregate(const UrlFinding *findings, size_t count)
{
    RiskCounts c;

    risk_count(findings, count, &c);

    if (c.high > 0 || c.suspicious >= 2)
        return URL_RISK_HIGH;
    if (c.suspicious >= 1 || c.low >= 2)
        return URL_RISK_SUSPICIOUS;
    return URL_RISK_LOW;
}

/* Índice del hallazgo de mayor severidad (el primero si hay empate) */
static size_t strongest_index(const UrlFinding *findings, size_t count)
{
    size_t best = 0;

    for (size_t i = 1; i < count; i++) {
        if (findings[i].severity > findings[best].severity)
            best = i;
    }
    return best;
}

int risk_explain(const UrlFinding *findings, size_t count, char *out, size_t size)
{
    RiskCounts c;
    UrlRisk level;
    int n;

    if (!out || size == 0)
        return -1;

    risk_count(findings, count, &c);
    level = risk_aggregate(findings, count);

    n = snprintf(out, size, "Nivel final: %s (altos: %zu, sospechosos: %zu, débiles: %zu).",
                 url_risk_name(level), c.high, c.suspicious, c.low);
    if (n < 0)
        return -1;

    if (count > 0) {
        const UrlFinding *f = &findings[strongest_index(findings, count)];
        size_t used = strlen(out);

        if (used < size - 1) {
            snprintf(out + used, size - used, " Motivo principal: %s", f->reason);
        }
    } else if (size > 0) {
        snprintf(out, size, "Nivel final: %s. No se encontraron indicadores.", url_risk_name(level));
    }

    return 0;
}
