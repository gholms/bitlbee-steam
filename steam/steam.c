/*
 * Copyright 2012-2014 James Geboski <jgeboski@gmail.com>
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

#include <stdarg.h>
#include <string.h>

#include "steam.h"
#include "steam-user.h"
#include "steam-util.h"

/**
 * Implemented #SteamNetFunc->error().
 *
 * @param net The #SteamNet.
 **/
void steam_func_error(SteamNet *net)
{
    SteamData *sata = net->data;

    imcb_error(sata->ic, "%s", net->err->message);
    //imc_logout(sata->ic, TRUE);
    imc_logout(sata->ic, FALSE);
}

/**
 * Implemented #SteamNetFunc->connected().
 *
 * @param net The #SteamNet.
 **/
void steam_func_connected(SteamNet *net)
{
    SteamData   *sata = net->data;
    account_t   *acc;
    const gchar *code;

    imcb_connected(sata->ic);

    acc  = sata->ic->acc;
    code = set_getstr(&acc->set, "authcode");
    steam_net_logon(net, acc->user, acc->pass, code);
}

/**
 * Implemented #SteamNetFunc->message().
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
void steam_func_message(SteamNet *net, const SteamMsg *msg)
{
    SteamData *sata = net->data;

    imcb_log(sata->ic, "Received message %d (0x%0x)", msg->type, msg->type);
}

/**
 * Implemented #set_eval for generic accounton operations. This simply
 * turns the account on as soon a value is set if it is not already
 * turned on.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_accounton(set_t *set, char *value)
{
    account_t *acc = set->data;

    if ((acc->ic != NULL) && (acc->ic->flags & OPT_LOGGED_IN))
        return value;

    /* Some hackery to auto connect upon authcode entry */

    g_free(set->value);
    set->value = g_strdup(value);

    account_on(acc->bee, acc);

    g_free(set->value);
    set->value = NULL;

    return value;
}

/**
 * Implemented #set_eval for the set of game_status.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_game_status(set_t *set, char *value)
{
    account_t *acc = set->data;
    SteamData *sata;

    if (!is_bool(value))
        return SET_INVALID;

    if (acc->ic == NULL)
        return value;

    sata = acc->ic->proto_data;
    sata->game_status = bool2int(value);

    return value;
}

/**
 * Implemented #set_eval for the set of show_playing. If the account
 * is on, this updates all buddies in all channels that are currently
 * in a game with the new user mode.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_show_playing(set_t *set, char *value)
{
    account_t  *acc = set->data;
    SteamData  *sata;
    SteamUser  *user;
    bee_user_t *bu;
    GSList     *l;
    gint        sply;

    if ((acc->ic == NULL) || (acc->ic->proto_data == NULL))
        return value;

    if (G_UNLIKELY(g_strcmp0(acc->prpl->name, "steam") != 0)) {
        g_warn_if_reached();
        return value;
    }

    sata = acc->ic->proto_data;
    sply = steam_user_chan_mode(value);

    if (sply == sata->show_playing)
        return value;

    sata->show_playing = sply;

    for (l = acc->bee->users; l; l = l->next) {
        bu   = l->data;
        user = bu->data;

        if (G_UNLIKELY((bu->ic != acc->ic) || (user == NULL))) {
            g_warn_if_reached();
            continue;
        }

        if (!(bu->flags & BEE_USER_ONLINE) || (user->game == NULL))
            continue;

        imcb_buddy_status(acc->ic, bu->handle, bu->flags,
                          bu->status, bu->status_msg);
        steam_user_chans_umode(user, sata->show_playing, TRUE);
    }

    return value;
}

/**
 * Implemented #set_eval for the set of password. If the account is on,
 * this disables the account, and resets the token. Then the plugin
 * will force the authentication process with the new password.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_password(set_t *set, char *value)
{
    account_t *acc = set->data;

    value = set_eval_account(set, value);
    set_reset(&acc->set, "token");

    if (acc->ic != NULL) {
        account_off(acc->bee, acc);
        account_on(acc->bee, acc);
    } else if (acc->reconnect != 0) {
        account_on(acc->bee, acc);
    }

    return value;
}

/**
 * Implements #prpl->init(). This initializes the an account.
 *
 * @param acc The #account_t.
 **/
static void steam_init(account_t *acc)
{
    set_t *s;

    s = set_add(&acc->set, "authcode", NULL, steam_eval_accounton, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_NOSAVE;

    s = set_add(&acc->set, "show_playing", "%", steam_eval_show_playing, acc);
    s->flags = SET_NULL_OK;

    set_add(&acc->set, "game_status", "false", steam_eval_game_status, acc);
    set_add(&acc->set, "password", NULL, steam_eval_password, acc);
}

/**
 * Implements #prpl->login(). This logins an account in.
 *
 * @param acc The #account_t.
 **/
static void steam_login(account_t *acc)
{
    SteamData *sata;

    sata = steam_data_new(acc);
    imcb_log(sata->ic, "Connecting");

    steam_net_connect_rand(sata->net);
}

/**
 * Implements #prpl->logout(). This logs an account out.
 *
 * @param ic The #im_connection.
 **/
static void steam_logout(struct im_connection *ic)
{
    SteamData *sata = ic->proto_data;

    steam_data_free(sata);
}

/**
 * Implements #prpl->buddy_msg(). This sends a message to a buddy.
 *
 * @param ic      The #im_connection.
 * @param to      The handle of the buddy.
 * @param message The message to send.
 * @param flags   The message flags. (Irrelevant to this plugin)
 *
 * @return 0. (Upstream bitlbe does nothing with this)
 **/
static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    return 0;
}

/**
 * Implements #prpl->send_typing(). This sends the typing state message.
 *
 * @param ic    The #im_connection.
 * @param who   The handle of the buddy.
 * @param flags The message flags. (Irrelevant to this plugin)
 *
 * @return 0. (Upstream bitlbe does nothing with this)
 **/
static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    return 0;
}

/**
 * Implements #prpl->add_buddy(). This adds a buddy.
 *
 * @param ic    The #im_connection.
 * @param name  The name of the buddy to add.
 * @param group The group of the buddy. (Irrelevant to this plugin)
 **/
static void steam_add_buddy(struct im_connection *ic, char *name, char *group)
{

}

/**
 * Implements #prpl->remove_buddy(). This removes a buddy.
 *
 * @param ic    The #im_connection.
 * @param name  The name of the buddy to add.
 * @param group The group of the buddy. (Irrelevant to this plugin)
 **/
static void steam_remove_buddy(struct im_connection *ic, char *name,
                               char *group)
{

}

/**
 * Implements #prpl->add_permit(). This is not used by the plugin.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_add_permit(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->add_deny(). This blocks a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_add_deny(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->rem_permit(). This is not used by the plugin.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_rem_permit(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->rem_deny(). This unblocks a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_rem_deny(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->get_info(). This retrieves the info of a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_get_info(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->auth_allow(). This accepts buddy requests.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_auth_allow(struct im_connection *ic, const char *who)
{

}

/**
 * Implements #prpl->auth_allow(). This denies buddy requests.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_auth_deny(struct im_connection *ic, const char *who)
{

}

/**
 * Implements #prpl->buddy_data_add(). This adds data to the buddy.
 *
 * @param bu The #bee_user_t.
 **/
static void steam_buddy_data_add(struct bee_user *bu)
{
    bu->data = steam_user_new(bu);
}

/**
 * Implements #prpl->buddy_data_free(). This frees the buddy data.
 *
 * @param bu The #bee_user_t.
 **/
static void steam_buddy_data_free(struct bee_user *bu)
{
    steam_user_free(bu->data);
}

/**
 * Implements the #init_plugin() function. BitlBee looks for this
 * function and executes it to register the protocol and its related
 * callbacks.
 **/
void init_plugin()
{
    struct prpl *pp;

    pp = g_new0(struct prpl, 1);

    pp->name            = "steam";
    pp->options         = OPT_NOOTR;
    pp->init            = steam_init;
    pp->login           = steam_login;
    pp->logout          = steam_logout;
    pp->buddy_msg       = steam_buddy_msg;
    pp->send_typing     = steam_send_typing;
    pp->add_buddy       = steam_add_buddy;
    pp->remove_buddy    = steam_remove_buddy;
    pp->add_permit      = steam_add_permit;
    pp->add_deny        = steam_add_deny;
    pp->rem_permit      = steam_rem_permit;
    pp->rem_deny        = steam_rem_deny;
    pp->get_info        = steam_get_info;
    pp->handle_cmp      = g_ascii_strcasecmp;
    pp->auth_allow      = steam_auth_allow;
    pp->auth_deny       = steam_auth_deny;
    pp->buddy_data_add  = steam_buddy_data_add;
    pp->buddy_data_free = steam_buddy_data_free;

    register_protocol(pp);
}

/**
 * Creates a new #SteamData with an #account_t. The returned #SteamData
 * should be freed with #steam_data_free() when no longer needed.
 *
 * @param acc The #account_t.
 *
 * @return The #SteamData or NULL on error.
 **/
SteamData *steam_data_new(account_t *acc)
{
    SteamData *sata;
    gchar     *str;

    static SteamNetFuncs funcs = {
        .error     = steam_func_error,
        .connected = steam_func_connected,
        .message   = steam_func_message
    };

    g_return_val_if_fail(acc != NULL, NULL);

    sata = g_new0(SteamData, 1);
    sata->net = steam_net_new(&funcs, sata);

    sata->ic = imcb_new(acc);
    sata->ic->proto_data = sata;

    sata->game_status = set_getbool(&acc->set, "game_status");

    str = set_getstr(&acc->set, "show_playing");
    sata->show_playing = steam_user_chan_mode(str);

    str = set_getstr(&acc->set, "machid");

    if (str != NULL) {
        g_byte_array_free(sata->net->machid, TRUE);
        sata->net->machid = steam_util_bytes_base64_dec(str);
    }

    str = set_getstr(&acc->set, "skey");

    if (str != NULL) {
        g_byte_array_free(sata->net->skey, TRUE);
        sata->net->skey = steam_util_bytes_base64_dec(str);
    }

    str = set_getstr(&acc->set, "sentry");

    if (str != NULL) {
        g_byte_array_free(sata->net->sentry, TRUE);
        sata->net->sentry = steam_util_bytes_base64_dec(str);
    }

    return sata;
}

/**
 * Frees all memory used by a #SteamData.
 *
 * @param sata The #SteamData.
 **/
void steam_data_free(SteamData *sata)
{
    if (G_UNLIKELY(sata == NULL))
        return;

    steam_net_free(sata->net);
    g_free(sata);
}
