/*
 * Copyright 2012 James Geboski <jgeboski@gmail.com>
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
#include "steam-http.h"
#include "steam-util.h"

typedef enum   _SteamApiType SteamApiType;
typedef struct _SteamApiPriv SteamApiPriv;

typedef void (*SteamParseFunc) (SteamApiPriv *priv, struct xt_node *xr);

enum _SteamApiType
{
    STEAM_PAIR_AUTH = 0,
    STEAM_PAIR_FRIENDS,
    STEAM_PAIR_LOGON,
    STEAM_PAIR_LOGOFF,
    STEAM_PAIR_MESSAGE,
    STEAM_PAIR_POLL,
    STEAM_PAIR_SUMMARIES,

    STEAM_PAIR_LAST
};

struct _SteamApiPriv
{
    SteamAPI     *api;
    SteamApiType  type;
    GError       *err;

    gpointer func;
    gpointer data;

    gpointer       rdata;
    GDestroyNotify rfunc;
};


static SteamApiPriv *steam_api_priv_new(SteamApiType type, SteamAPI *api,
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
    g_return_if_fail(priv != NULL);

    if ((priv->rfunc != NULL) && (priv->rdata != NULL))
        priv->rfunc(priv->rdata);

    if (priv->err != NULL)
        g_error_free(priv->err);

    g_free(priv);
}

GQuark steam_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-api-error-quark");

    return q;
}

SteamAPI *steam_api_new(const gchar *umqid)
{
    SteamAPI *api;
    GRand    *rand;

    api = g_new0(SteamAPI, 1);

    if (umqid == NULL) {
        rand       = g_rand_new();
        api->umqid = g_strdup_printf("%u", g_rand_int(rand));

        g_rand_free(rand);
    } else {
        api->umqid = g_strdup(umqid);
    }

    api->http = steam_http_new(STEAM_API_AGENT,
                               (GDestroyNotify) steam_api_priv_free);

    return api;
}

void steam_api_free(SteamAPI *api)
{
    g_return_if_fail(api != NULL);

    steam_http_free(api->http);

    g_free(api->token);
    g_free(api->steamid);
    g_free(api->umqid);
    g_free(api->lmid);
    g_free(api);
}

static void steam_slist_free_full(GSList *list)
{
    g_slist_free_full(list, g_free);
}

static void steam_api_auth_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    SteamApiError  err;
    gchar         *text;

    if (steam_util_xn_text(xr, "access_token", &text)) {
        g_free(priv->api->token);
        priv->api->token = g_strdup(text);
        return;
    }

    if (steam_util_xn_cmp(xr, "x_errorcode", "steamguard_code_required", &text))
        err = STEAM_API_ERROR_AUTH_REQ;
    else
        err = STEAM_API_ERROR_AUTH;

    steam_util_xn_text(xr, "error_description", &text);
    g_set_error(&priv->err, STEAM_API_ERROR, err, text);
}

static void steam_api_friends_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;
    gchar          *text;
    GSList         *fl;

    if (!steam_util_xn_node(xr, "friends", &xn) || (xn->children == NULL))
        goto error;

    fl = NULL;

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xn_cmp(xn, "relationship", "friend", &text))
            continue;

        if (!steam_util_xn_text(xn, "steamid", &text))
            continue;

        fl = g_slist_prepend(fl, text);
    }

    priv->rdata = fl;
    priv->rfunc = (GDestroyNotify) g_slist_free;

    if (fl != NULL)
        return;

error:
    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIENDS,
                "Empty friends list");
}

static void steam_api_logon_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    gchar *text;

    if (!steam_util_xn_cmp(xr, "error", "OK", &text)) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGON, text);
        return;
    }

    steam_util_xn_text(xr, "steamid", &text);
    g_free(priv->api->steamid);
    priv->api->steamid = g_strdup(text);

    steam_util_xn_text(xr, "message", &text);
    g_free(priv->api->lmid);
    priv->api->lmid = g_strdup(text);
}

static void steam_api_logoff_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    gchar *text;

    if (steam_util_xn_cmp(xr, "error", "OK", &text))
        return;

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF, text);
}

static void steam_api_message_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    gchar *text;

    if (steam_util_xn_cmp(xr, "error", "OK", &text))
        return;

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_MESSAGE, text);
}

static void steam_api_poll_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;
    gchar          *text;
    GSList         *mu;
    SteamMessage    sm;

    if (!steam_util_xn_cmp(xr, "messagelast", priv->api->lmid, &text)) {
        g_free(priv->api->lmid);
        priv->api->lmid = g_strdup(text);
    }

    if (!steam_util_xn_cmp(xr, "error", "Timeout", &text)) {
        if (g_strcmp0(text, "OK")) {
            g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                        text);
            return;
        }
    }

    if (!steam_util_xn_node(xr, "messages", &xn) || (xn->children == NULL))
        return;

    mu = NULL;

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        memset(&sm, 0, sizeof sm);

        if (steam_util_xn_cmp(xn, "steamid_from", priv->api->steamid, &text))
            continue;

        sm.steamid = text;

        if (!steam_util_xn_text(xn, "type", &text))
            continue;

        if (!g_strcmp0("personastate", text)) {
            if (!steam_util_xn_text(xn, "persona_name", &text))
                continue;

            sm.type = STEAM_MESSAGE_TYPE_STATE;
            sm.nick = text;

            if (!steam_util_xn_text(xn, "persona_state", &text))
                continue;

            sm.state = g_ascii_strtoll(text, NULL, 10);
        } else if (!g_strcmp0("saytext", text)) {
            if (!steam_util_xn_text(xn, "text", &text))
                continue;

            sm.type = STEAM_MESSAGE_TYPE_SAYTEXT;
            sm.text = text;
        } else if (!g_strcmp0("typing", text)) {
            sm.type = STEAM_MESSAGE_TYPE_TYPING;
        } else if (!g_strcmp0("emote", text)) {
            if (!steam_util_xn_text(xn, "text", &text))
                continue;

            sm.type = STEAM_MESSAGE_TYPE_EMOTE;
            sm.text = text;
        } else if (!g_strcmp0("leftconversation", text)) {
            sm.type = STEAM_MESSAGE_TYPE_LEFT_CONV;
        } else if (!g_strcmp0("personarelationship", text)) {
            if (!steam_util_xn_text(xn, "persona_state", &text))
                continue;

            sm.type  = STEAM_MESSAGE_TYPE_RELATIONSHIP;
            sm.state = g_ascii_strtoll(text, NULL, 10);
        } else {
            continue;
        }

        mu = g_slist_prepend(mu, g_memdup(&sm, sizeof sm));
    }

    priv->rdata = mu;
    priv->rfunc = (GDestroyNotify) steam_slist_free_full;
}

static void steam_api_summaries_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;
    gchar          *text;
    GSList         *mu;
    SteamSummary   *ss;

    if (!steam_util_xn_node(xr, "players", &xn) || (xn->children == NULL))
        goto error;

    mu = NULL;

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xn_text(xn, "steamid", &text))
            continue;

        ss = g_new0(SteamSummary, 1);
        ss->steamid = text;

        steam_util_xn_text(xn, "gameextrainfo", &text);
        ss->game = text;

        steam_util_xn_text(xn, "gameserverip", &text);
        ss->server = text;

        steam_util_xn_text(xn, "personaname", &text);
        ss->nick = text;

        steam_util_xn_text(xn, "profileurl", &text);
        ss->profile = text;

        steam_util_xn_text(xn, "realname", &text);
        ss->fullname = text;

        if (steam_util_xn_text(xn, "personastate", &text))
            ss->state = g_ascii_strtoll(text, NULL, 10);

        mu = g_slist_prepend(mu, ss);
    }

    priv->rdata = mu;
    priv->rfunc = (GDestroyNotify) steam_slist_free_full;

    if (mu != NULL)
        return;

error:
    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARIES,
                "No friends returned");
}

static gboolean steam_api_cb(SteamHttpReq *req, gpointer data)
{
    SteamApiPriv     *priv = data;
    struct xt_parser *xt;

    SteamParseFunc pf[STEAM_PAIR_LAST];

    if ((priv->type < 0) || (priv->type > STEAM_PAIR_LAST))
        return TRUE;

    xt = NULL;

    if (req->err != NULL) {
        g_propagate_error(&priv->err, req->err);
        req->err = NULL;
        goto parse;
    }

    if (req->body_size < 1) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_EMPTY_REPLY,
                    "Empty HTTP reply");
        goto parse;
    }

    xt = xt_new(NULL, NULL);

    if (xt_feed(xt, req->body, req->body_size) < 0) {
        g_propagate_error(&priv->err, xt->gerr);
        xt->gerr = NULL;
        goto parse;
    }

parse:
    pf[STEAM_PAIR_AUTH]      = steam_api_auth_cb;
    pf[STEAM_PAIR_FRIENDS]   = steam_api_friends_cb;
    pf[STEAM_PAIR_LOGON]     = steam_api_logon_cb;
    pf[STEAM_PAIR_LOGOFF]    = steam_api_logoff_cb;
    pf[STEAM_PAIR_MESSAGE]   = steam_api_message_cb;
    pf[STEAM_PAIR_POLL]      = steam_api_poll_cb;
    pf[STEAM_PAIR_SUMMARIES] = steam_api_summaries_cb;

    if ((priv->err == NULL) && (xt != NULL))
        pf[priv->type](priv, xt->root);

    if (priv->func != NULL) {
        switch (priv->type) {
        case STEAM_PAIR_AUTH:
        case STEAM_PAIR_LOGON:
        case STEAM_PAIR_LOGOFF:
        case STEAM_PAIR_MESSAGE:
            ((SteamApiFunc) priv->func)(priv->api, priv->err, priv->data);
            break;

        case STEAM_PAIR_FRIENDS:
        case STEAM_PAIR_POLL:
        case STEAM_PAIR_SUMMARIES:
            ((SteamListFunc) priv->func)(priv->api, priv->rdata, priv->err,
                                         priv->data);
            break;
        }
    }

    if (xt != NULL)
        xt_free(xt);

    return TRUE;
}

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    const gchar *user, const gchar *pass,
                    SteamApiFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_AUTH, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_AUTH, steam_api_cb, priv);

    steam_http_req_headers_set(req, 1, "User-Agent", STEAM_API_AGENT_AUTH);

    steam_http_req_params_set(req, 8,
        "format",          "xml",
        "client_id",       STEAM_API_CLIENT_ID,
        "grant_type",      "password",
        "username",        user,
        "password",        pass,
        "x_emailauthcode", authcode,
        "x_webcookie",     NULL,
        "scope", "read_profile write_profile read_client write_client"
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_friends(SteamAPI *api, SteamListFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_FRIENDS, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_FRIENDS, steam_api_cb, priv);

    steam_http_req_params_set(req, 4,
        "format",       "xml",
        "access_token", api->token,
        "steamid",      api->steamid,
        "relationship", "friend"
    );

    req->flags = STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_logon(SteamAPI *api, SteamApiFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_LOGON, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_LOGON, steam_api_cb, priv);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_logoff(SteamAPI *api, SteamApiFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_LOGOFF, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_LOGOFF, steam_api_cb, priv);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_message(SteamAPI *api, SteamMessage *sm, SteamApiFunc func,
                       gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);
    g_return_if_fail(sm  != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_MESSAGE, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_MESSAGE, steam_api_cb, priv);

    steam_http_req_params_set(req, 5,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid,
        "steamid_dst",  sm->steamid,
        "type",         steam_message_type_str(sm->type)
    );

    switch (sm->type) {
    case STEAM_MESSAGE_TYPE_SAYTEXT:
    case STEAM_MESSAGE_TYPE_EMOTE:
        steam_http_req_params_set(req, 1, "text", sm->text);
        break;

    case STEAM_MESSAGE_TYPE_TYPING:
        break;

    default:
        steam_http_req_free(req);
        return;
    }

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_poll(SteamAPI *api, SteamListFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_POLL, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_POLL, steam_api_cb, priv);

    steam_http_req_headers_set(req, 1, "Connection", "Keep-Alive");

    steam_http_req_params_set(req, 5,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid,
        "message",      api->lmid,
        "sectimeout",   STEAM_API_KEEP_ALIVE
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_summaries(SteamAPI *api, GSList *friends, SteamListFunc func,
                         gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    GSList *s;
    GSList *e;
    GSList *l;

    gsize size;
    gint  i;

    gchar *str;
    gchar *p;

    g_return_if_fail(api != NULL);

    if (friends == NULL) {
        if (func != NULL)
            func(api, NULL, NULL, data);

        return;
    }

    s  = friends;

    while (TRUE) {
        size = 0;

        for (l = s, i = 0; (l != NULL) && (i < 100); l = l->next, i++)
            size += strlen(l->data) + 1;

        str = g_new0(gchar, size);
        p   = g_stpcpy(str, s->data);
        e   = l;

        for (l = s->next; l != e; l = l->next) {
            p = g_stpcpy(p, ",");
            p = g_stpcpy(p, l->data);
        }

        priv = steam_api_priv_new(STEAM_PAIR_SUMMARIES, api, func, data);
        req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                                  STEAM_PATH_SUMMARIES, steam_api_cb, priv);

        steam_http_req_params_set(req, 3,
            "format",       "xml",
            "access_token", api->token,
            "steamids",     str
        );

        g_free(str);

        req->flags = STEAM_HTTP_FLAG_SSL;
        steam_http_req_send(req);

        if (e != NULL)
            s = e->next;
        else
            break;
    }
}

void steam_api_summary(SteamAPI *api, const gchar *steamid, SteamListFunc func,
                       gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api     != NULL);
    g_return_if_fail(steamid != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_SUMMARIES, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_SUMMARIES, steam_api_cb, priv);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "steamids",     steamid
    );

    req->flags = STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

gchar *steam_message_type_str(SteamMessageType type)
{
    gchar *strs[STEAM_MESSAGE_TYPE_LAST];

    if ((type < 0) || (type > STEAM_MESSAGE_TYPE_LAST))
        return "";

    strs[STEAM_MESSAGE_TYPE_SAYTEXT]      = "saytext";
    strs[STEAM_MESSAGE_TYPE_EMOTE]        = "emote";
    strs[STEAM_MESSAGE_TYPE_LEFT_CONV]    = "leftconversation";
    strs[STEAM_MESSAGE_TYPE_RELATIONSHIP] = "personarelationship";
    strs[STEAM_MESSAGE_TYPE_STATE]        = "personastate";
    strs[STEAM_MESSAGE_TYPE_TYPING]       = "typing";

    return strs[type];
}

gchar *steam_state_str(SteamState state)
{
    gchar *strs[STEAM_STATE_LAST];

    if ((state < 0) || (state > STEAM_STATE_LAST))
        return "";

    strs[STEAM_STATE_OFFLINE] = "Offline";
    strs[STEAM_STATE_ONLINE]  = "Online";
    strs[STEAM_STATE_BUSY]    = "Busy";
    strs[STEAM_STATE_AWAY]    = "Away";
    strs[STEAM_STATE_SNOOZE]  = "Snooze";

    return strs[state];
}

SteamState steam_state_from_str(const gchar *state)
{
    gchar *s;
    guint  i;

    if (state == NULL)
        return STEAM_STATE_OFFLINE;

    for (i = 0; i < STEAM_STATE_LAST; i++) {
        s = steam_state_str(i);

        if (!g_ascii_strcasecmp(state, s))
            return i;
    }

    return STEAM_STATE_OFFLINE;
}
