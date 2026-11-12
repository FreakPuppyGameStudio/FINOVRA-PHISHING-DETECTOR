#include "database.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#define SCHEMA_VERSION 2

struct Database {
    sqlite3 *handle;
};

/* Esquema base (versión 1) */
static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS url_scans ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  url TEXT NOT NULL,"
    "  risk INTEGER NOT NULL,"
    "  summary TEXT NOT NULL,"
    "  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))"
    ");"
    "CREATE TABLE IF NOT EXISTS email_analyses ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  message_id TEXT,"
    "  sender TEXT,"
    "  reply_to TEXT,"
    "  subject TEXT,"
    "  risk INTEGER NOT NULL,"
    "  summary TEXT NOT NULL,"
    "  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))"
    ");"
    "CREATE TABLE IF NOT EXISTS email_urls ("
    "  email_id INTEGER NOT NULL REFERENCES email_analyses(id) ON DELETE CASCADE,"
    "  url TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS campaigns ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  member_count INTEGER NOT NULL,"
    "  signals INTEGER NOT NULL,"
    "  summary TEXT NOT NULL,"
    "  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))"
    ");"
    "CREATE TABLE IF NOT EXISTS campaign_members ("
    "  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,"
    "  email_id INTEGER NOT NULL REFERENCES email_analyses(id) ON DELETE CASCADE"
    ");";

/* Índices para el historial y el panel (versión 2) */
static const char *INDEXES_V2 =
    "CREATE INDEX IF NOT EXISTS idx_url_scans_created ON url_scans(created_at);"
    "CREATE INDEX IF NOT EXISTS idx_url_scans_risk ON url_scans(risk);"
    "CREATE INDEX IF NOT EXISTS idx_email_analyses_created ON email_analyses(created_at);"
    "CREATE INDEX IF NOT EXISTS idx_email_analyses_risk ON email_analyses(risk);"
    "CREATE INDEX IF NOT EXISTS idx_email_urls_email ON email_urls(email_id);"
    "CREATE INDEX IF NOT EXISTS idx_campaign_members_email ON campaign_members(email_id);";

/* ------------------------------------------------------------------ */
/* Utilidades                                                          */
/* ------------------------------------------------------------------ */

static int exec_sql(sqlite3 *h, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(h, sql, NULL, NULL, &err);

    if (err)
        sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

static int prepare(sqlite3 *h, const char *sql, sqlite3_stmt **st)
{
    return sqlite3_prepare_v2(h, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}

/* Texto vacío o NULL se guarda como NULL */
static void bind_text_or_null(sqlite3_stmt *st, int idx, const char *s)
{
    if (s && s[0] != '\0')
        sqlite3_bind_text(st, idx, s, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, idx);
}

static int count_value(sqlite3 *h, const char *sql, int64_t *out)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (prepare(h, sql, &st) != 0)
        return -1;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW)
        *out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* Crea los índices de la versión 2 si la base aún está en la versión 1 */
static int migrate(sqlite3 *h)
{
    int64_t version = 0;

    if (count_value(h, "PRAGMA user_version;", &version) != 0)
        return -1;
    if (version >= SCHEMA_VERSION)
        return 0;

    if (exec_sql(h, INDEXES_V2) != 0)
        return -1;
    return exec_sql(h, "PRAGMA user_version = 2;");
}

/* ------------------------------------------------------------------ */
/* Apertura                                                            */
/* ------------------------------------------------------------------ */

int db_open(const char *path, Database **out)
{
    sqlite3 *h = NULL;
    Database *db;

    if (!path || !out)
        return -1;
    *out = NULL;

    if (sqlite3_open(path, &h) != SQLITE_OK) {
        if (h)
            sqlite3_close(h);
        return -1;
    }

    /* Sin esto SQLite no respeta las llaves foráneas ni el ON DELETE CASCADE */
    if (exec_sql(h, "PRAGMA foreign_keys = ON;") != 0 ||
        exec_sql(h, SCHEMA) != 0 ||
        migrate(h) != 0) {
        sqlite3_close(h);
        return -1;
    }

    db = calloc(1, sizeof *db);
    if (!db) {
        sqlite3_close(h);
        return -1;
    }
    db->handle = h;
    *out = db;
    return 0;
}

void db_close(Database *db)
{
    if (!db)
        return;
    sqlite3_close(db->handle);
    free(db);
}

const char *db_last_error(const Database *db)
{
    if (!db || !db->handle)
        return "";
    return sqlite3_errmsg(db->handle);
}

/* ------------------------------------------------------------------ */
/* Guardado                                                            */
/* ------------------------------------------------------------------ */

int db_save_url_scan(Database *db, const char *url, UrlRisk risk,
                     const char *summary, int64_t *out_id)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!db || !url || !summary)
        return -1;
    if (prepare(db->handle, "INSERT INTO url_scans(url, risk, summary) VALUES(?1, ?2, ?3);", &st) != 0)
        return -1;

    sqlite3_bind_text(st, 1, url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, (int)risk);
    sqlite3_bind_text(st, 3, summary, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    if (out_id)
        *out_id = sqlite3_last_insert_rowid(db->handle);
    return 0;
}

int db_save_email(Database *db, const EmailMessage *m, UrlRisk risk,
                  const char *summary, int64_t *out_id)
{
    sqlite3_stmt *st = NULL;
    int64_t email_id;
    int rc;

    if (!db || !m || !summary)
        return -1;
    if (exec_sql(db->handle, "BEGIN IMMEDIATE;") != 0)
        return -1;

    if (prepare(db->handle,
                "INSERT INTO email_analyses(message_id, sender, reply_to, subject, risk, summary) "
                "VALUES(?1, ?2, ?3, ?4, ?5, ?6);", &st) != 0)
        goto fail;

    bind_text_or_null(st, 1, m->message_id);
    bind_text_or_null(st, 2, m->from);
    bind_text_or_null(st, 3, m->reply_to);
    bind_text_or_null(st, 4, m->subject);
    sqlite3_bind_int(st, 5, (int)risk);
    sqlite3_bind_text(st, 6, summary, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE)
        goto fail;

    email_id = sqlite3_last_insert_rowid(db->handle);

    if (prepare(db->handle, "INSERT INTO email_urls(email_id, url) VALUES(?1, ?2);", &st) != 0)
        goto fail;
    for (size_t i = 0; i < m->url_count; i++) {
        sqlite3_bind_int64(st, 1, email_id);
        sqlite3_bind_text(st, 2, m->urls[i], -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            st = NULL;
            goto fail;
        }
    }
    sqlite3_finalize(st);
    st = NULL;

    if (exec_sql(db->handle, "COMMIT;") != 0)
        goto fail;

    if (out_id)
        *out_id = email_id;
    return 0;

fail:
    if (st)
        sqlite3_finalize(st);
    exec_sql(db->handle, "ROLLBACK;");
    return -1;
}

int db_save_campaign(Database *db, const Campaign *c,
                     const int64_t *email_ids, size_t id_count, int64_t *out_id)
{
    sqlite3_stmt *st = NULL;
    int64_t campaign_id;
    int rc;

    if (!db || !c || (!email_ids && c->member_count > 0))
        return -1;
    for (size_t i = 0; i < c->member_count; i++) {
        if (c->members[i] >= id_count)
            return -1;
    }

    if (exec_sql(db->handle, "BEGIN IMMEDIATE;") != 0)
        return -1;

    if (prepare(db->handle,
                "INSERT INTO campaigns(member_count, signals, summary) VALUES(?1, ?2, ?3);", &st) != 0)
        goto fail;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)c->member_count);
    sqlite3_bind_int(st, 2, (int)c->signals);
    sqlite3_bind_text(st, 3, c->summary, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE)
        goto fail;

    campaign_id = sqlite3_last_insert_rowid(db->handle);

    if (prepare(db->handle,
                "INSERT INTO campaign_members(campaign_id, email_id) VALUES(?1, ?2);", &st) != 0)
        goto fail;
    for (size_t i = 0; i < c->member_count; i++) {
        sqlite3_bind_int64(st, 1, campaign_id);
        sqlite3_bind_int64(st, 2, email_ids[c->members[i]]);
        rc = sqlite3_step(st);
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            st = NULL;
            goto fail;
        }
    }
    sqlite3_finalize(st);
    st = NULL;

    if (exec_sql(db->handle, "COMMIT;") != 0)
        goto fail;

    if (out_id)
        *out_id = campaign_id;
    return 0;

fail:
    if (st)
        sqlite3_finalize(st);
    exec_sql(db->handle, "ROLLBACK;");
    return -1;
}

/* ------------------------------------------------------------------ */
/* Borrado                                                             */
/* ------------------------------------------------------------------ */

int db_clear_history(Database *db)
{
    if (!db)
        return -1;

    /* El orden importa aunque haya ON DELETE CASCADE: primero lo que depende de otro */
    if (exec_sql(db->handle, "BEGIN IMMEDIATE;") != 0)
        return -1;
    if (exec_sql(db->handle,
                 "DELETE FROM campaign_members;"
                 "DELETE FROM campaigns;"
                 "DELETE FROM email_urls;"
                 "DELETE FROM email_analyses;"
                 "DELETE FROM url_scans;") != 0) {
        exec_sql(db->handle, "ROLLBACK;");
        return -1;
    }
    if (exec_sql(db->handle, "COMMIT;") != 0) {
        exec_sql(db->handle, "ROLLBACK;");
        return -1;
    }

    /* Recupera el espacio en disco; si falla no afecta al borrado */
    exec_sql(db->handle, "VACUUM;");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Consultas                                                           */
/* ------------------------------------------------------------------ */

int db_stats(Database *db, DbStats *out)
{
    if (!db || !out)
        return -1;
    memset(out, 0, sizeof *out);

    if (count_value(db->handle, "SELECT COUNT(*) FROM url_scans;", &out->url_scans) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM email_analyses;", &out->emails) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM email_urls;", &out->email_urls) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM campaigns;", &out->campaigns) != 0)
        return -1;
    if (count_value(db->handle,
                    "SELECT (SELECT COUNT(*) FROM url_scans WHERE risk = 2) + "
                    "(SELECT COUNT(*) FROM email_analyses WHERE risk = 2);",
                    &out->high_risk) != 0)
        return -1;
    return 0;
}

int db_risk_breakdown(Database *db, DbRiskBreakdown *out)
{
    if (!db || !out)
        return -1;
    memset(out, 0, sizeof *out);

    /* Valores de UrlRisk: 0 = bajo, 1 = sospechosa, 2 = alto */
    if (count_value(db->handle, "SELECT COUNT(*) FROM url_scans WHERE risk = 0;", &out->url_low) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM url_scans WHERE risk = 1;", &out->url_suspicious) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM url_scans WHERE risk = 2;", &out->url_high) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM email_analyses WHERE risk = 0;", &out->email_low) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM email_analyses WHERE risk = 1;", &out->email_suspicious) != 0)
        return -1;
    if (count_value(db->handle, "SELECT COUNT(*) FROM email_analyses WHERE risk = 2;", &out->email_high) != 0)
        return -1;
    return 0;
}

int db_recent_text(Database *db, size_t limit, char *out, size_t size)
{
    sqlite3_stmt *st = NULL;
    size_t used = 0;

    if (!db || !out || size == 0)
        return -1;
    out[0] = '\0';

    if (prepare(db->handle,
                "SELECT created_at, 'URL', url, summary FROM url_scans "
                "UNION ALL "
                "SELECT created_at, 'Correo', COALESCE(subject, '(sin asunto)'), summary "
                "FROM email_analyses "
                "ORDER BY created_at DESC LIMIT ?1;", &st) != 0)
        return -1;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)limit);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *when = (const char *)sqlite3_column_text(st, 0);
        const char *kind = (const char *)sqlite3_column_text(st, 1);
        const char *what = (const char *)sqlite3_column_text(st, 2);
        const char *summ = (const char *)sqlite3_column_text(st, 3);
        int n = snprintf(out + used, size - used, "%s  [%s] %s\n    %s\n\n",
                         when ? when : "", kind ? kind : "", what ? what : "", summ ? summ : "");

        if (n < 0 || (size_t)n >= size - used)
            break;
        used += (size_t)n;
    }

    sqlite3_finalize(st);
    return 0;
}
