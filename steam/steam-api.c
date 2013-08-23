/*
 * Copyright 2012-2013 James Geboski <jgeboski@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "steam-api.h"
#include "steam-glib.h"
#include "steam-http.h"
#include "steam-json.h"

typedef enum   _SteamApiFlags SteamApiFlags;
typedef enum   _SteamApiType  SteamApiType;
typedef struct _SteamApiPriv  SteamApiPriv;

typedef void (*SteamParseFunc) (SteamApiPriv *priv, json_value *json);

enum _SteamApiFlags
{
    STEAM_API_FLAG_NOCALL = 1 << 0,
    STEAM_API_FLAG_NOFREE = 1 << 1
};

enum _SteamApiType
{
    STEAM_API_TYPE_AUTH = 0,
    STEAM_API_TYPE_FRIENDS,
    STEAM_API_TYPE_KEY,
    STEAM_API_TYPE_LOGOFF,
    STEAM_API_TYPE_LOGON,
    STEAM_API_TYPE_RELOGON,
    STEAM_API_TYPE_MESSAGE,
    STEAM_API_TYPE_POLL,
    STEAM_API_TYPE_SUMMARY,

    STEAM_API_TYPE_LAST
};

struct _SteamApiPriv
{
    SteamApi      *api;
    SteamApiFlags  flags;
    SteamApiType   type;
    GError        *err;

    gpointer func;
    gpointer data;

    gpointer       rdata;
    GDestroyNotify rfunc;

    GList        *sums;
    SteamHttpReq *req;
};

static void steam_api_summaries(SteamApiPriv *priv);
static const gchar *steam_api_type_str(SteamApiType type);
static SteamMessageType steam_message_type_from_str(const gchar *type);

GQuark steam_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-api-error-quark");

    return q;
}

SteamApi *steam_api_new(const gchar *umqid)
{
    SteamApi *api;
    GRand    *rand;

    api = g_new0(SteamApi, 1);

    if (umqid == NULL) {
        rand       = g_rand_new();
        api->umqid = g_strdup_printf("%" G_GUINT32_FORMAT, g_rand_int(rand));

        g_rand_free(rand);
    } else {
        api->umqid = g_strdup(umqid);
    }

    api->http = steam_http_new(STEAM_API_AGENT);
    return api;
}

void steam_api_free(SteamApi *api)
{
    g_return_if_fail(api != NULL);

    if (api->auth != NULL)
        steam_auth_free(api->auth);

    steam_http_free(api->http);

    g_free(api->token);
    g_free(api->umqid);
    g_free(api->steamid);
    g_free(api);
}

SteamMessage *steam_message_new(const gchar *steamid)
{
    SteamMessage *sm;

    sm = g_new0(SteamMessage, 1);
    sm->ss = steam_summary_new(steamid);

    return sm;
}

void steam_message_free(SteamMessage *sm)
{
    g_return_if_fail(sm != NULL);

    if (sm->ss != NULL)
        steam_summary_free(sm->ss);

    g_free(sm->text);
    g_free(sm);
}

SteamSummary *steam_summary_new(const gchar *steamid)
{
    SteamSummary *ss;

    ss = g_new0(SteamSummary, 1);
    ss->fstate  = STEAM_FRIEND_STATE_NONE;
    ss->steamid = g_strdup(steamid);

    return ss;
}

void steam_summary_free(SteamSummary *ss)
{
    g_return_if_fail(ss != NULL);

    g_free(ss->server);
    g_free(ss->game);
    g_free(ss->profile);
    g_free(ss->fullname);
    g_free(ss->nick);
    g_free(ss->steamid);
    g_free(ss);
}

static void steam_summary_json(SteamSummary *ss, json_value *json)
{
    const gchar  *str;
    gint64        in;

    steam_json_str(json, "gameextrainfo", &str);
    ss->game = g_strdup(str);

    steam_json_str(json, "gameserverip", &str);
    ss->server = g_strdup(str);

    steam_json_str(json, "personaname", &str);
    ss->nick = g_strdup(str);

    steam_json_str(json, "profileurl", &str);
    ss->profile = g_strdup(str);

    steam_json_str(json, "realname", &str);
    ss->fullname = g_strdup(str);

    steam_json_int(json, "personastate", &in);
    ss->state = in;
}

static SteamApiPriv *steam_api_priv_new(SteamApi *api, SteamApiType type,
                                        gpointer func, gpointer data)
{
    SteamApiPriv *priv;

    priv = g_new0(SteamApiPriv, 1);

    priv->api  = api;
    priv->type = type;
    priv->func = func;
    priv->data = data;

    return priv;
}

static void steam_api_priv_free(SteamApiPriv *priv)
{
    if ((priv->rfunc != NULL) && (priv->rdata != NULL))
        priv->rfunc(priv->rdata);

    if (priv->sums != NULL)
        g_list_free(priv->sums);

    if (priv->err != NULL)
        g_error_free(priv->err);

    g_free(priv);
}

static void steam_api_priv_func(SteamApiPriv *priv)
{
    g_return_if_fail(priv != NULL);

    if (priv->func == NULL)
        return;

    switch (priv->type) {
    case STEAM_API_TYPE_AUTH:
    case STEAM_API_TYPE_KEY:
    case STEAM_API_TYPE_LOGOFF:
    case STEAM_API_TYPE_LOGON:
    case STEAM_API_TYPE_RELOGON:
    case STEAM_API_TYPE_MESSAGE:
        ((SteamApiFunc) priv->func)(priv->api, priv->err, priv->data);
        return;

    case STEAM_API_TYPE_FRIENDS:
    case STEAM_API_TYPE_POLL:
        ((SteamListFunc) priv->func)(priv->api, priv->rdata, priv->err,
                                     priv->data);
        return;

    case STEAM_API_TYPE_SUMMARY:
        ((SteamSummaryFunc) priv->func)(priv->api, priv->rdata, priv->err,
                                        priv->data);
        return;

    default:
        return;
    }
}

static void steam_api_priv_relogon(SteamApiPriv *priv)
{
    g_return_if_fail(priv != NULL);

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGON_EXPIRED,
                "Logon session expired");

    steam_http_queue_pause(priv->api->http, TRUE);
    steam_http_req_resend(priv->req);
}

static void steam_api_auth_cb(SteamApiPriv *priv, json_value *json)
{
    SteamApiError  err;
    const gchar   *str;

    if (steam_json_str(json, "captcha_gid", &str))
        steam_auth_captcha(priv->api->auth, str);

    if (steam_json_str(json, "emailsteamid", &str))
        steam_auth_email(priv->api->auth, str);

    if (!steam_json_bool(json, "success")) {
        if (steam_json_bool(json, "emailauth_needed"))
            err = STEAM_API_ERROR_AUTH_GUARD;
        else if (steam_json_bool(json, "captcha_needed"))
            err = STEAM_API_ERROR_AUTH_CAPTCHA;
        else
            err = STEAM_API_ERROR_AUTH;

        if (!steam_json_str(json, "message", &str))
            str = "Failed to authenticate";

        g_set_error(&priv->err, STEAM_API_ERROR, err, "%s", str);
        return;
    }

    if (!steam_json_str(json, "oauth", &str)) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth data");
        return;
    }

    json = steam_json_new(str, &priv->err);

    if (json == NULL)
        return;

    if (!steam_json_str(json, "oauth_token", &str)) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth token");
    }

    g_free(priv->api->token);
    priv->api->token = g_strdup(str);
    json_value_free(json);
}

static void steam_api_friends_free(GSList *friends)
{
    g_slist_free_full(friends, (GDestroyNotify) steam_summary_free);
}

static void steam_api_friends_cb(SteamApiPriv *priv, json_value *json)
{
    json_value   *jv;
    json_value   *je;
    GSList       *friends;
    SteamSummary *ss;
    const gchar  *str;
    guint         i;

    if (!steam_json_val(json, "friends", json_array, &jv))
        return;

    friends = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_scmp(je, "relationship", "friend", &str))
            continue;

        if (!steam_json_str(je, "steamid", &str))
            continue;

        ss         = steam_summary_new(str);
        friends    = g_slist_prepend(friends, ss);
        priv->sums = g_list_prepend(priv->sums, ss);
    }

    priv->rdata = friends;
    priv->rfunc = (GDestroyNotify) steam_api_friends_free;
}

static void steam_api_key_cb(SteamApiPriv *priv, json_value *json)
{
    SteamAuth   *auth;
    const gchar *str;

    if (steam_json_scmp(json, "success", "false", &str))
        goto error;

    auth = (priv->api->auth != NULL) ? priv->api->auth : steam_auth_new();

    if (!steam_json_str(json, "publickey_mod", &str) ||
        !steam_auth_key_mod(auth, str))
        goto error;

    if (!steam_json_str(json, "publickey_exp", &str) ||
        !steam_auth_key_exp(auth, str))
        goto error;

    if (steam_json_str(json, "timestamp", &str))
        auth->time = g_strdup(str);

    priv->api->auth = auth;
    return;

error:
    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_KEY,
                "Failed to retrieve authentication key");
}

static void steam_api_logon_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar *str;
    gint64       in;

    if (!steam_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGON,
                    "%s", str);
        return;
    }

    steam_json_int(json, "message", &in);
    priv->api->lmid = in;

    if (!steam_json_scmp(json, "steamid", priv->api->steamid, &str)) {
        g_free(priv->api->steamid);
        priv->api->steamid = g_strdup(str);
    }

    if (!steam_json_scmp(json, "umqid", priv->api->umqid, &str)) {
        g_free(priv->api->umqid);
        priv->api->umqid = g_strdup(str);
    }
}

static void steam_api_relogon_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar  *str;

    steam_http_queue_pause(priv->api->http, FALSE);

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_RELOGON,
                "%s", str);
}

static void steam_api_logoff_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar *str;

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

static void steam_api_message_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar *str;

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
        steam_api_priv_relogon(priv);
        return;
    }

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

static void steam_api_poll_free(GSList *messages)
{
    g_slist_free_full(messages, (GDestroyNotify) steam_message_free);
}

static void steam_api_poll_cb(SteamApiPriv *priv, json_value *json)
{
    json_value   *jv;
    json_value   *je;
    GSList       *messages;
    SteamMessage *sm;
    const gchar  *str;
    gint64        in;
    guint         i;

    steam_json_int(json, "messagelast", &in);
    priv->api->lmid = in;

    if (steam_json_str(json, "error", &str)  &&
        (g_ascii_strcasecmp(str, "Timeout") != 0) &&
        (g_ascii_strcasecmp(str, "OK")      != 0)) {

        if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
            steam_api_priv_relogon(priv);
            return;
        }

        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                    "%s", str);
        return;
    }

    if (!steam_json_val(json, "messages", json_array, &jv))
        return;

    messages = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (steam_json_scmp(je, "steamid_from", priv->api->steamid, &str))
            continue;

        sm = steam_message_new(str);

        steam_json_str(je, "type", &str);
        steam_json_int(je, "utc_timestamp", &in);

        sm->type   = steam_message_type_from_str(str);
        sm->tstamp = in;

        switch (sm->type) {
        case STEAM_MESSAGE_TYPE_SAYTEXT:
        case STEAM_MESSAGE_TYPE_EMOTE:
            steam_json_str(je, "text", &str);
            sm->text = g_strdup(str);
            break;

        case STEAM_MESSAGE_TYPE_STATE:
            steam_json_str(je, "persona_name", &str);
            sm->ss->nick = g_strdup(str);
            priv->sums   = g_list_prepend(priv->sums, sm->ss);
            break;

        case STEAM_MESSAGE_TYPE_RELATIONSHIP:
            steam_json_int(je, "persona_state", &in);
            sm->ss->fstate = in;
            priv->sums     = g_list_prepend(priv->sums, sm->ss);
            break;

        case STEAM_MESSAGE_TYPE_TYPING:
        case STEAM_MESSAGE_TYPE_LEFT_CONV:
            break;

        default:
            steam_message_free(sm);
            continue;
        }

        messages = g_slist_prepend(messages, sm);
    }

    priv->rdata = g_slist_reverse(messages);
    priv->rfunc = (GDestroyNotify) steam_api_poll_free;
}

static void steam_api_summaries_cb(SteamApiPriv *priv, json_value *json)
{
    json_value   *jv;
    json_value   *je;
    SteamSummary *ss;
    const gchar  *str;
    GList        *l;
    GList        *c;
    guint         i;

    if (!steam_json_val(json, "players", json_array, &jv))
        return;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str(je, "steamid", &str))
            continue;

        for (l = priv->sums; l != NULL; ) {
            ss = l->data;

            if (g_strcmp0(ss->steamid, str) != 0) {
                l = l->next;
                continue;
            }

            c = l;
            l = l->next;
            priv->sums = g_list_delete_link(priv->sums, c);
            steam_summary_json(ss, je);
        }
    }

    steam_api_summaries(priv);
}

static void steam_api_summary_cb(SteamApiPriv *priv, json_value *json)
{
    json_value   *jv;
    SteamSummary *ss;
    const gchar  *str;

    if (!steam_json_val(json, "players", json_array, &jv))
        return;

    if (jv->u.array.length < 1)
        return;

    jv = jv->u.array.values[0];

    if (!steam_json_str(jv, "steamid", &str))
        return;

    ss = steam_summary_new(str);
    steam_summary_json(ss, jv);

    priv->rdata = ss;
    priv->rfunc = (GDestroyNotify) steam_summary_free;
}

static void steam_api_cb(SteamHttpReq *req, gpointer data)
{
    SteamApiPriv *priv = data;
    json_value   *json;

    static const SteamParseFunc saf[STEAM_API_TYPE_LAST] = {
        [STEAM_API_TYPE_AUTH]    = steam_api_auth_cb,
        [STEAM_API_TYPE_FRIENDS] = steam_api_friends_cb,
        [STEAM_API_TYPE_KEY]     = steam_api_key_cb,
        [STEAM_API_TYPE_LOGOFF]  = steam_api_logoff_cb,
        [STEAM_API_TYPE_LOGON]   = steam_api_logon_cb,
        [STEAM_API_TYPE_RELOGON] = steam_api_relogon_cb,
        [STEAM_API_TYPE_MESSAGE] = steam_api_message_cb,
        [STEAM_API_TYPE_POLL]    = steam_api_poll_cb,
        [STEAM_API_TYPE_SUMMARY] = steam_api_summary_cb
    };

    if ((priv->type < 0) || (priv->type > STEAM_API_TYPE_LAST))
        return;

    if (req->err != NULL) {
        g_propagate_error(&priv->err, req->err);
        req->err = NULL;
        json = NULL;
        goto parse;
    }

    json = steam_json_new(req->body, &priv->err);

parse:
    if ((priv->err == NULL) && (json != NULL)) {
        if (priv->sums == NULL) {
            saf[priv->type](priv, json);

            if (priv->sums != NULL)
                steam_api_summaries(priv);
        } else {
            steam_api_summaries_cb(priv, json);
        }
    }

    if (priv->err != NULL)
        g_prefix_error(&priv->err, "%s: ", steam_api_type_str(priv->type));

    if (!(priv->flags & STEAM_API_FLAG_NOCALL))
        steam_api_priv_func(priv);

    if (json != NULL)
        json_value_free(json);

    if (priv->req->flags & STEAM_HTTP_REQ_FLAG_NOFREE)
        priv->flags |= STEAM_API_FLAG_NOFREE;

    if (!(priv->flags & STEAM_API_FLAG_NOFREE)) {
        priv->req = NULL;
        steam_api_priv_free(priv);
    } else {
        priv->flags &= ~(STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE);
    }
}

static void steam_api_priv_req(SteamApiPriv *priv, gchar *host, gchar *path)
{
    SteamApi     *api = priv->api;
    SteamHttpReq *req;

    req = steam_http_req_new(api->http, host, 443, path, steam_api_cb, priv);

    req->flags = STEAM_HTTP_REQ_FLAG_SSL;
    priv->req  = req;
}

void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data)
{
    SteamApiPriv *priv;
    GTimeVal      tv;
    gchar        *pswd;
    gchar        *ms;

    g_return_if_fail(api       != NULL);
    g_return_if_fail(api->auth != NULL);

    pswd = steam_auth_key_encrypt(api->auth, pass);
    priv = steam_api_priv_new(api, STEAM_API_TYPE_AUTH, func, data);

    if (pswd == NULL) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to encrypt password");

        steam_api_priv_func(priv);
        steam_api_priv_free(priv);
        return;
    }

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));
    steam_api_priv_req(priv, STEAM_COM_HOST, STEAM_COM_PATH_AUTH);

    steam_http_req_params_set(priv->req, 11,
        "username",        user,
        "password",        pswd,
        "emailauth",       authcode,
        "emailsteamid",    api->auth->esid,
        "captchagid",      api->auth->cgid,
        "captcha_text",    captcha,
        "rsatimestamp",    api->auth->time,
        "oauth_client_id", STEAM_API_CLIENT_ID,
        "donotcache",      ms,
        "remember_login",  "true",
        "oauth_scope", "read_profile write_profile read_client write_client"
    );

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);

    g_free(pswd);
    g_free(ms);
}

void steam_api_friends(SteamApi *api, SteamListFunc func, gpointer data)
{
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(api, STEAM_API_TYPE_FRIENDS, func, data);
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_FRIENDS);

    steam_http_req_params_set(priv->req, 3,
        "access_token", api->token,
        "steamid",      api->steamid,
        "relationship", "friend"
    );

    steam_http_req_send(priv->req);
}

void steam_api_key(SteamApi *api, const gchar *user, SteamApiFunc func,
                   gpointer data)
{
    SteamApiPriv *priv;
    GTimeVal      tv;
    gchar        *ms;

    g_return_if_fail(api != NULL);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    priv = steam_api_priv_new(api, STEAM_API_TYPE_KEY, func, data);
    steam_api_priv_req(priv, STEAM_COM_HOST, STEAM_COM_PATH_KEY);

    steam_http_req_params_set(priv->req, 2,
        "username",   user,
        "donotcache", ms
    );

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);
    g_free(ms);
}

void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(api, STEAM_API_TYPE_LOGOFF, func, data);
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_LOGOFF);

    steam_http_req_params_set(priv->req, 2,
        "access_token", api->token,
        "umqid",        api->umqid
    );

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);
}

void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(api, STEAM_API_TYPE_LOGON, func, data);
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(priv->req, 2,
        "access_token", api->token,
        "umqid",        api->umqid
    );

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);
}

void steam_api_relogon(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(api, STEAM_API_TYPE_RELOGON, func, data);
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(priv->req, 2,
        "access_token", api->token,
        "umqid",        api->umqid
    );

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);
}

void steam_api_message(SteamApi *api, const SteamMessage *sm,
                       SteamApiFunc func, gpointer data)
{
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);
    g_return_if_fail(sm  != NULL);

    priv = steam_api_priv_new(api, STEAM_API_TYPE_MESSAGE, func, data);
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_MESSAGE);

    steam_http_req_params_set(priv->req, 4,
        "access_token", api->token,
        "umqid",        api->umqid,
        "steamid_dst",  sm->ss->steamid,
        "type",         steam_message_type_str(sm->type)
    );

    switch (sm->type) {
    case STEAM_MESSAGE_TYPE_SAYTEXT:
    case STEAM_MESSAGE_TYPE_EMOTE:
        steam_http_req_params_set(priv->req, 1, "text", sm->text);
        break;

    case STEAM_MESSAGE_TYPE_TYPING:
        break;

    default:
        steam_http_req_free(priv->req);
        return;
    }

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_QUEUED | STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);
}

void steam_api_poll(SteamApi *api, SteamListFunc func, gpointer data)
{
    SteamApiPriv *priv;
    gchar        *lmid;

    g_return_if_fail(api != NULL);

    lmid = g_strdup_printf("%" G_GINT64_FORMAT, api->lmid);
    priv = steam_api_priv_new(api, STEAM_API_TYPE_POLL, func, data);

    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_POLL);
    steam_http_req_headers_set(priv->req, 1, "Connection", "Keep-Alive");

    steam_http_req_params_set(priv->req, 4,
        "access_token", api->token,
        "umqid",        api->umqid,
        "message",      lmid,
        "sectimeout",   STEAM_API_KEEP_ALIVE
    );

    priv->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(priv->req);
    g_free(lmid);
}

static void steam_api_summaries(SteamApiPriv *priv)
{
    SteamSummary *ss;
    GHashTable   *tbl;
    GString      *gstr;
    GList        *l;
    gsize         i;

    if (priv->sums == NULL)
        return;

    priv->flags |= STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE;

    tbl  = g_hash_table_new(g_str_hash, g_str_equal);
    gstr = g_string_sized_new(2048);

    for (l = priv->sums, i = 0; l != NULL; l = l->next) {
        ss = l->data;

        if (g_hash_table_contains(tbl, ss->steamid))
            continue;

        g_hash_table_add(tbl, ss->steamid);
        g_string_append_printf(gstr, "%s,", ss->steamid);

        if ((++i % 100) == 0)
            break;
    }

    /* Remove trailing comma */
    gstr->str[gstr->len - 1] = 0;
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(priv->req, 2,
        "access_token", priv->api->token,
        "steamids",     gstr->str
    );

    steam_http_req_send(priv->req);
    g_string_free(gstr, TRUE);
    g_hash_table_destroy(tbl);
}

void steam_api_summary(SteamApi *api, const gchar *steamid,
                       SteamSummaryFunc func, gpointer data)
{
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(api, STEAM_API_TYPE_SUMMARY, func, data);
    steam_api_priv_req(priv, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(priv->req, 2,
        "access_token", api->token,
        "steamids",     steamid
    );

    steam_http_req_send(priv->req);
}

static const gchar *steam_api_type_str(SteamApiType type)
{
    static const gchar *strs[STEAM_API_TYPE_LAST] = {
        [STEAM_API_TYPE_AUTH]    = "Authentication",
        [STEAM_API_TYPE_FRIENDS] = "Friends",
        [STEAM_API_TYPE_KEY]     = "Key",
        [STEAM_API_TYPE_LOGON]   = "Logon",
        [STEAM_API_TYPE_RELOGON] = "Relogon",
        [STEAM_API_TYPE_LOGOFF]  = "Logoff",
        [STEAM_API_TYPE_MESSAGE] = "Message",
        [STEAM_API_TYPE_POLL]    = "Polling",
        [STEAM_API_TYPE_SUMMARY] = "Summary"
    };

    if ((type < 0) || (type > STEAM_API_TYPE_LAST))
        return "Generic";

    return strs[type];
}

const gchar *steam_message_type_str(SteamMessageType type)
{
    static const gchar *strs[STEAM_MESSAGE_TYPE_LAST] = {
        [STEAM_MESSAGE_TYPE_SAYTEXT]      = "saytext",
        [STEAM_MESSAGE_TYPE_EMOTE]        = "emote",
        [STEAM_MESSAGE_TYPE_LEFT_CONV]    = "leftconversation",
        [STEAM_MESSAGE_TYPE_RELATIONSHIP] = "personarelationship",
        [STEAM_MESSAGE_TYPE_STATE]        = "personastate",
        [STEAM_MESSAGE_TYPE_TYPING]       = "typing"
    };

    if ((type < 0) || (type > STEAM_MESSAGE_TYPE_LAST))
        return "";

    return strs[type];
}

const gchar *steam_state_str(SteamState state)
{
    static const gchar *strs[STEAM_STATE_LAST] = {
        [STEAM_STATE_OFFLINE] = "Offline",
        [STEAM_STATE_ONLINE]  = "Online",
        [STEAM_STATE_BUSY]    = "Busy",
        [STEAM_STATE_AWAY]    = "Away",
        [STEAM_STATE_SNOOZE]  = "Snooze",
        [STEAM_STATE_TRADE]   = "Looking to Trade",
        [STEAM_STATE_PLAY]    = "Looking to Play"
    };

    if ((state < 0) || (state > STEAM_STATE_LAST))
        return "Offline";

    return strs[state];
}

static SteamMessageType steam_message_type_from_str(const gchar *type)
{
    const gchar *s;
    guint        i;

    if (type == NULL)
        return STEAM_MESSAGE_TYPE_LAST;

    for (i = 0; i < STEAM_MESSAGE_TYPE_LAST; i++) {
        s = steam_message_type_str(i);

        if (g_ascii_strcasecmp(type, s) == 0)
            return i;
    }

    return STEAM_MESSAGE_TYPE_LAST;
}

SteamState steam_state_from_str(const gchar *state)
{
    const gchar *s;
    guint        i;

    if (state == NULL)
        return STEAM_STATE_OFFLINE;

    for (i = 0; i < STEAM_STATE_LAST; i++) {
        s = steam_state_str(i);

        if (g_ascii_strcasecmp(state, s) == 0)
            return i;
    }

    return STEAM_STATE_OFFLINE;
}
