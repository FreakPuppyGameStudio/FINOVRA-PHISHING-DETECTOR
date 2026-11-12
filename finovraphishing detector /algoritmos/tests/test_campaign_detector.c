#include <stdio.h>
#include <string.h>

#include "campaign_detector.h"

static int failures = 0;

static const char *RAW[] = {
    /* 0: phishing con enlace y asunto */
    "From: PayPal Soporte <soporte@paypal-seguridad.xyz>\n"
    "Subject: Acción requerida\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Tu cuenta será suspendida. Verifica tu identidad en "
    "https://paypal-seguridad.xyz/verificar hoy mismo.\n",

    /* 1: mismo enlace y asunto respondido, otro remitente */
    "From: Cuenta <otro@correo-rapido.top>\n"
    "Subject: Re: Acción requerida\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Revisa tu cuenta: https://paypal-seguridad.xyz/verificar gracias\n",

    /* 2: correo normal, sin relación */
    "From: Equipo <equipo@empresa.com>\n"
    "Subject: Reunion manana\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Agenda para la reunion de manana con el equipo de ventas y finanzas del trimestre.\n",

    /* 3: solo comparte asunto con 0 y 1; no debe agruparse */
    "From: Otro <otro@empresa.com>\n"
    "Subject: Acción requerida\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n",

    /* 4 y 5: mismo remitente y texto casi idéntico */
    "From: Banco <aviso@banco-mx.com>\n"
    "Subject: Estado de cuenta\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Su estado de cuenta ya está disponible en nuestra app. Revise los movimientos de este "
    "mes y confirme sus datos en el portal oficial del banco.\n",

    "From: Banco <aviso@banco-mx.com>\n"
    "Subject: Aviso mensual\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Su estado de cuenta ya está disponible en nuestra app. Revise los movimientos de este "
    "mes y confirme sus datos en el portal oficial del banco.\n"
};
#define RAW_COUNT (sizeof RAW / sizeof RAW[0])

static EmailMessage emails[RAW_COUNT];

static void check(bool cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok:   %s\n", what);
    }
}

/* Busca una campaña cuyos miembros son exactamente a y b */
static const Campaign *find_pair(const CampaignReport *r, size_t a, size_t b)
{
    for (size_t c = 0; c < r->campaign_count; c++) {
        const Campaign *camp = &r->campaigns[c];
        bool has_a = false;
        bool has_b = false;

        if (camp->member_count != 2)
            continue;
        for (size_t m = 0; m < camp->member_count; m++) {
            if (camp->members[m] == a) has_a = true;
            if (camp->members[m] == b) has_b = true;
        }
        if (has_a && has_b)
            return camp;
    }
    return NULL;
}

/* true si el índice aparece en alguna campaña */
static bool in_any_campaign(const CampaignReport *r, size_t idx)
{
    for (size_t c = 0; c < r->campaign_count; c++) {
        for (size_t m = 0; m < r->campaigns[c].member_count; m++) {
            if (r->campaigns[c].members[m] == idx)
                return true;
        }
    }
    return false;
}

int main(void)
{
    static CampaignReport report;

    printf("--- Parseo de entrada ---\n");
    for (size_t i = 0; i < RAW_COUNT; i++) {
        if (email_parse(RAW[i], strlen(RAW[i]), &emails[i]) != 0) {
            printf("FAIL: no se pudo parsear el correo %zu\n", i);
            failures++;
        }
    }
    printf("ok:   %zu correos parseados\n", RAW_COUNT);

    printf("\n--- Correlación ---\n");
    check(campaign_detect(emails, RAW_COUNT, &report) == 0, "campaign_detect devuelve 0");
    check(report.campaign_count == 2, "dos campañas detectadas");

    const Campaign *phish = find_pair(&report, 0, 1);
    const Campaign *bank = find_pair(&report, 4, 5);

    check(phish != NULL, "correos 0 y 1 forman una campaña (enlace + asunto)");
    check(bank != NULL, "correos 4 y 5 forman una campaña (mismo remitente + texto)");

    if (phish) {
        check((phish->signals & CAMPAIGN_SIG_SHARED_URL) != 0, "campaña 0-1 incluye enlace idéntico");
        check((phish->signals & CAMPAIGN_SIG_SUBJECT_EQUAL) != 0, "campaña 0-1 incluye mismo asunto");
        check(strstr(phish->summary, "Campaña de 2 correos") != NULL, "resumen cuenta los correos");
        printf("      resumen: %s\n", phish->summary);
    }
    if (bank) {
        check((bank->signals & CAMPAIGN_SIG_BODY_SIMILAR) != 0, "campaña 4-5 incluye texto parecido");
        check((bank->signals & CAMPAIGN_SIG_SAME_SENDER) != 0, "campaña 4-5 incluye mismo remitente");
        printf("      resumen: %s\n", bank->summary);
    }

    check(!in_any_campaign(&report, 2), "correo normal (2) no se agrupa");
    check(!in_any_campaign(&report, 3), "asunto compartido solo (3) no basta para agrupar");

    printf("\n--- Casos límite ---\n");
    {
        static CampaignReport empty;

        check(campaign_detect(NULL, 0, &empty) == 0 && empty.campaign_count == 0,
              "sin correos: cero campañas");
        check(campaign_detect(NULL, 3, &empty) != 0, "puntero nulo con correos se rechaza");
        check(campaign_detect(emails, 1, &empty) == 0 && empty.campaign_count == 0,
              "un solo correo: cero campañas");
    }
    {
        char text[256];

        campaign_describe(CAMPAIGN_SIG_SHARED_URL | CAMPAIGN_SIG_SUBJECT_EQUAL, text, sizeof text);
        check(strcmp(text, "enlace idéntico, mismo asunto") == 0, "describe las señales en español");
        campaign_describe(0, text, sizeof text);
        check(strcmp(text, "nada en común") == 0, "sin señales dice nada en común");
    }

    for (size_t i = 0; i < RAW_COUNT; i++)
        email_free(&emails[i]);

    printf("\n");
    if (failures == 0) {
        printf("Todas las pruebas pasaron.\n");
        return 0;
    }
    printf("%d prueba(s) fallaron.\n", failures);
    return 1;
}
