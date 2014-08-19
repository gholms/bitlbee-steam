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

#include "steam-crypt.h"
#include "steam-msgs.h"
#include "steam-net.h"
#include "steam-util.h"

/**
 * Gets the error domain for #SteamNet.
 *
 * @return The #GQuark of the error domain.
 **/
GQuark steam_net_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-net-error-quark");

    return q;
}

/**
 * Creates a new #SteamNet. The returned #SteamNet should be freed with
 * #steam_net_free() when no longer needed.
 *
 *  @param funcs The #SteamNetFuncs.
 *  @param data  The user defined data or NULL.
 *
 * @return The #SteamNet or NULL on error.
 **/
SteamNet *steam_net_new(const SteamNetFuncs *funcs, gpointer data)
{
    SteamNet *net;

    g_return_val_if_fail(funcs != NULL, NULL);

    net = g_new0(SteamNet, 1);
    net->funcs  = (SteamNetFuncs*) g_memdup(funcs, sizeof *funcs);
    net->data   = data;
    net->univ   = STEAM_ID_UNIV_UNKNOWN;
    net->skey   = g_byte_array_new();
    net->machid = g_byte_array_new();
    net->sentry = g_byte_array_new();
    net->rbuf   = g_byte_array_new();
    net->wbuf   = g_byte_array_new();
    net->fd     = -1;

    g_byte_array_set_size(net->machid, 32);
    random_bytes(net->machid->data, net->machid->len);

    return net;
}

/**
 * Frees all memory used by a #SteamNet.
 *
 * @param net The #SteamNet.
 **/
void steam_net_free(SteamNet *net)
{
    if (G_UNLIKELY(net == NULL))
        return;

    steam_net_close(net);
    steam_net_evt_free(net->cevt);
    g_clear_error(&net->err);

    g_byte_array_free(net->wbuf,   TRUE);
    g_byte_array_free(net->rbuf,   TRUE);
    g_byte_array_free(net->machid, TRUE);
    g_byte_array_free(net->sentry, TRUE);
    g_byte_array_free(net->skey,   TRUE);

    g_free(net->funcs);
    g_free(net);
}

/**
 * Closes the #SteamNet connection.
 *
 * @param net The #SteamNet.
 **/
void steam_net_close(SteamNet *net)
{
    g_return_if_fail(net != NULL);

    if (G_LIKELY(net->cevt != NULL))
        net->cevt->func = NULL;

    b_event_remove(net->tev);
    b_event_remove(net->rev);
    b_event_remove(net->wev);

    if (net->fd >= 0)
        closesocket(net->fd);

    g_byte_array_set_size(net->rbuf, 0);
    g_byte_array_set_size(net->wbuf, 0);

    net->univ  = STEAM_ID_UNIV_UNKNOWN;
    net->flags =  0;
    net->fd    = -1;
    net->tev   =  0;
    net->rev   =  0;
    net->wev   =  0;
    net->remz  =  0;
    net->wemz  =  0;
}

/**
 * Handles an error with the #SteamNet. This sets #SteamNet->err, calls
 * the error function, and closes the connection.
 *
 * @param net  The #SteamNet.
 * @param errc The #SteamNetError.
 * @param fmt  The format string.
 * @param ...  The arguments for the format string.
 **/
void steam_net_error(SteamNet *net, SteamNetError errc, const gchar *fmt, ...)
{
    gchar   *str;
    va_list  ap;

    g_return_if_fail(net != NULL);
    g_return_if_fail(fmt != NULL);

    va_start(ap, fmt);
    str = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    g_clear_error(&net->err);
    g_set_error_literal(&net->err, STEAM_NET_ERROR, errc, str);

    STEAM_UTIL_DEBUGLN("Error: %s", net->err->message);
    STEAM_NET_FUNC(net, error);
    g_free(str);
}

/**
 * Creates a new #SteamNetEvt. The returned #SteamNetEvt should be freed
 * with #steam_net_evt_free() when no longer needed.
 *
 * @param net The #SteamNet.
 *
 * @return The #SteamNetEvt or NULL on error.
 **/
SteamNetEvt *steam_net_evt_new(SteamNet *net, b_event_handler func)
{
    SteamNetEvt *evt;

    g_return_val_if_fail(net != NULL, NULL);

    evt = g_new0(SteamNetEvt, 1);
    evt->net  = net;
    evt->func = func;

    return evt;
}

/**
 * Frees all memory used by a #SteamNetEvt.
 *
 * @param evt The #SteamNetEvt.
 **/
void steam_net_evt_free(SteamNetEvt *evt)
{
    if (G_UNLIKELY(evt == NULL))
        return;

    g_free(evt);
}

/**
 * Implemented #b_event_handler for executing #SteamNetEvt->func.
 *
 * @param data The user defined data, which is #SteamNetEv.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
gboolean steam_net_evt_exec(gpointer data, gint fd, b_input_condition cond)
{
    SteamNetEvt *evt = data;

    g_return_val_if_fail(evt      != NULL, FALSE);
    g_return_val_if_fail(evt->net != NULL, FALSE);

    if (G_UNLIKELY(evt->func != NULL)) {
        if (evt->func(evt->net, evt->net->fd, 0))
            return TRUE;
    }

    return FALSE;
}

/**
 * Implemented #b_event_handler for the read of #SteamNet->fd.
 *
 * @param data The user defined data, which is #SteamNet.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
static gboolean steam_net_cb_read(gpointer data, gint fd,
                                  b_input_condition cond)
{
    SteamNet *net = data;
    guint32   size;
    guint32   magic;
    gssize    rize;
    gsize     oset;

    if (net->remz < 1) {
        if (read(net->fd, &size, sizeof size) != sizeof size) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                            "Failed to read size");
            return FALSE;
        }

        if (read(net->fd, &magic, sizeof magic) != sizeof magic) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                            "Failed to read magic");
            return FALSE;
        }

        if (magic != STEAM_MSG_MAGIC) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                            "Invalid packet magic");
            return FALSE;
        }

        g_byte_array_set_size(net->rbuf, size);
        net->remz = size;
    }

    oset = net->rbuf->len - net->remz;
    rize = read(net->fd, net->rbuf->data + oset, net->remz);
    net->remz -= rize;

    if (rize < 0) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Failed to read data");
        return FALSE;
    }

    if (net->remz < 1)
        steam_net_read(net, net->rbuf, net->flags & STEAM_NET_FLAG_ENCRYPT);

    return TRUE;
}

/**
 * Implemented #b_event_handler for handling connection timeouts.
 *
 * @param data The user defined data, which is #SteamNet.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return FALSE to prevent continued event handling.
 **/
static gboolean steam_net_cb_timeout(gpointer data, gint fd,
                                     b_input_condition cond)
{
    SteamNet *net = data;

    if (G_LIKELY(net->cevt != NULL))
        net->cevt->func = NULL;

    net->tev = 0;
    steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Connection timed out");
    return FALSE;
}

/**
 * Implemented #b_event_handler for the connection of #SteamNet->fd.
 *
 * @param data The user defined data, which is #SteamNet.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
static gboolean steam_net_cb_connect(gpointer data, gint fd,
                                     b_input_condition cond)
{
    SteamNet *net = data;

    if (fd < 0) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Failed to connect");
        return FALSE;
    }

    if (G_LIKELY(net->cevt != NULL)) {
        steam_net_evt_free(net->cevt);
        net->cevt = NULL;
    }

    b_event_remove(net->tev);

    net->tev = 0;
    net->rev = b_input_add(fd, B_EV_IO_READ, steam_net_cb_read, net);
    return TRUE;
}

/**
 * Connects the #SteamNet to a hostname:port. The connection should
 * closed with #steam_net_close() when no longer needed.
 *
 * @param net  The #SteamNet.
 * @param host The hostname or address.
 * @param port The port number.
 **/
void steam_net_connect(SteamNet *net, const gchar *host, gint port)
{
    g_return_if_fail(net  != NULL);
    g_return_if_fail(host != NULL);

    steam_net_close(net);
    net->cevt = steam_net_evt_new(net, steam_net_cb_connect);
    net->fd   = proxy_connect(host, port, steam_net_evt_exec, net->cevt);
    net->tev  = b_timeout_add(STEAM_NET_TIMEOUT, steam_net_cb_timeout, net);

    if (net->fd < 0)
        steam_net_cb_connect(net, net->fd, 0);
}

/**
 * Connects the #SteamNet to a hostname:port. This connects with via a
 * randomly selected Steam hostname:port. The connection should closed
 * with #steam_net_close() when no longer needed.
 *
 * @param net  The #SteamNet.
 **/
void steam_net_connect_rand(SteamNet *net)
{
    gint32 r;

    static SteamNetHost hosts[] = {
        {"146.66.152.12",  27019}
/*
        {"72.165.61.174",  27017},
        {"72.165.61.174",  27018},
        {"72.165.61.175",  27017},
        {"72.165.61.175",  27018},
        {"72.165.61.176",  27017},
        {"72.165.61.176",  27018},
        {"72.165.61.185",  27017},
        {"72.165.61.185",  27018},
        {"72.165.61.187",  27017},
        {"72.165.61.187",  27018},
        {"72.165.61.188",  27017},
        {"72.165.61.188",  27018},
        {"146.66.152.12",  27017},
        {"146.66.152.12",  27018},
        {"146.66.152.12",  27019},
        {"146.66.152.13",  27017},
        {"146.66.152.13",  27018},
        {"146.66.152.13",  27019},
        {"146.66.152.14",  27017},
        {"146.66.152.14",  27018},
        {"146.66.152.14",  27019},
        {"146.66.152.15",  27017},
        {"146.66.152.15",  27018},
        {"146.66.152.15",  27019},
        {"209.197.29.196", 27017},
        {"209.197.29.197", 27017}
*/
    };

    r = g_random_int_range(0, G_N_ELEMENTS(hosts));
    STEAM_UTIL_DEBUGLN("Using Steam host %s:%d", hosts[r].name, hosts[r].port);
    steam_net_connect(net, hosts[r].name, hosts[r].port);
}

/**
 * Checks the #SteamNet connection.
 *
 * @param net   The #SteamNet.
 * @param error TRUE to error upon no connection, FALSE otherwise.
 *
 * @return TRUE if the #SteamNet is connected, FALSE otherwise.
 **/
gboolean steam_net_connected(SteamNet *net, gboolean error)
{
    gboolean connected;

    g_return_val_if_fail(net != NULL, FALSE);

    connected = net->fd >= 0;

    if (!connected && error) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Not connected");
        return connected;
    }

    return connected;
}

/**
 * Reads an incoming #SteamMsgChanEncReq.
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
static void steam_net_read_msg_chan_enc_req(SteamNet *net, const SteamMsg *msg)
{
    SteamMsgChanEncReq *req = msg->msg;
    SteamMsg           *res;
    GByteArray         *ckey;
    guint32             crc;

    static const guint32 zero = 0;

    net->univ = req->univ;
    g_byte_array_set_size(net->skey, 32);
    random_bytes(net->skey->data, net->skey->len);
    ckey = steam_crypt_rsa_enc_univ(req->univ, net->skey);

    if (ckey == NULL) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                        "Failed to encrypt session token");
        return;
    }

    crc = steam_crypt_crc32(ckey);
    res = steam_msg_new(STEAM_MSG_TYPE_CHAN_ENC_RES);

    g_byte_array_append(res->poad, ckey->data, ckey->len);
    g_byte_array_append(res->poad, (guint8*) &crc,  sizeof crc);
    g_byte_array_append(res->poad, (guint8*) &zero, sizeof zero);

    steam_net_write_msg(net, res);
    g_byte_array_free(ckey, TRUE);
    steam_msg_free(res);
}

/**
 * Reads an incoming #SteamMsgChanEncRlt.
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
static void steam_net_read_msg_chan_enc_rlt(SteamNet *net, const SteamMsg *msg)
{
    SteamMsgChanEncRlt *rlt = msg->msg;

    if (rlt->rlt != STEAM_MSG_RLT_TYPE_OK) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Encryption failed (%d)",
                        rlt->rlt);
        return;
    }

    net->flags |= STEAM_NET_FLAG_ENCRYPT;
    STEAM_NET_FUNC(net, connected);
}

/**
 * Reads an incoming #CMsgClientLogonResponse.
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
static void steam_net_read_msg_clt_logon_res(SteamNet *net, const SteamMsg *msg)
{
    CMsgClientLogonResponse *res = msg->msg;

    if (res->eresult != STEAM_MSG_RLT_TYPE_OK) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Logon failed (%d)",
                        res->eresult);
        return;
    }

    
}

/**
 * Reads an incoming multi #SteamMsg.
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
static void steam_net_read_msg_multi(SteamNet *net, const SteamMsg *msg)
{
    CMsgMulti  *tsg = msg->msg;
    GByteArray *cytes;
    GByteArray *bytes;
    GByteArray *mytes;
    guint32     size;
    guint       i;

    bytes = g_byte_array_new();
    g_byte_array_append(bytes, tsg->message_body.data, tsg->message_body.len);

    if (tsg->size_unzipped > 0) {
        cytes = bytes;
        bytes = steam_util_gzip_inf(bytes, tsg->size_unzipped);
        g_byte_array_free(cytes, TRUE);

        if (bytes == NULL) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Failed to inflate");
            return;
        }
    }

    for (i = 0; i < bytes->len;) {
        if ((i + sizeof size) > bytes->len) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                            "Failed to read sub-message size");
            g_byte_array_free(bytes, TRUE);
            return;
        }

        memcpy(&size, bytes->data + i, sizeof size);
        i += sizeof size;

        if ((i + size) > bytes->len) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                            "Failed to read sub-message");
            g_byte_array_free(bytes, TRUE);
            return;
        }

        mytes = g_byte_array_new();
        g_byte_array_append(mytes, bytes->data + i, size);
        i += size;

        steam_net_read(net, mytes, FALSE);
        g_byte_array_free(mytes, TRUE);
    }

    g_byte_array_free(bytes, TRUE);
}

/**
 * Read a #GByteArray to the #SteamNet. This will optionally decrypt the
 * message.
 *
 * @param net     The #SteamNet.
 * @param bytes   The #GByteArray.
 * @param decrypt TRUE to decrypt the message, otherwise FALSE.
 **/
void steam_net_read(SteamNet *net, const GByteArray *bytes, gboolean decrypt)
{
    GByteArray *cytes;
    SteamMsg   *msg;
    guint32     type;
    guint32     rype;

    g_return_if_fail(net   != NULL);
    g_return_if_fail(bytes != NULL);

    if (bytes->len < sizeof type) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Invalid message");
        return;
    }

    if (decrypt) {
        cytes = steam_crypt_sym_dec(net->skey, net->rbuf);

        if (cytes == NULL) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                        "Failed to decrypt message");
            return;
        }

        memcpy(&type, cytes->data, sizeof type);
        msg = steam_msg_unpack(cytes);
        g_byte_array_free(cytes, TRUE);
    } else {
        memcpy(&type, bytes->data, sizeof type);
        msg = steam_msg_unpack(bytes);
    }

    if (msg == NULL) {
        rype = (type & STEAM_MSG_PMASK) ? (type & ~STEAM_MSG_PMASK) : type;
        steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                        "Failed to unpack message %u (0x%0X)",
                        rype, type);
        return;
    }

    steam_net_read_msg(net, msg);
    steam_msg_free(msg);
}

/**
 * Reads a #SteamMsg to the #SteamNet.
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
void steam_net_read_msg(SteamNet *net, const SteamMsg *msg)
{
    guint32 type;
    guint32 rype;

    void (*hndlfunc) (SteamNet *net, const SteamMsg *msg);

    static const SteamUtilEnum enums[] = {
        {STEAM_MSG_TYPE_CHAN_ENC_REQ,  steam_net_read_msg_chan_enc_req},
        {STEAM_MSG_TYPE_CHAN_ENC_RLT,  steam_net_read_msg_chan_enc_rlt},
        {STEAM_MSG_TYPE_CLT_LOGON_RES, steam_net_read_msg_clt_logon_res},
        {STEAM_MSG_TYPE_MUTLI,         steam_net_read_msg_multi},
        STEAM_UTIL_ENUM_NULL
    };

    g_return_if_fail(net != NULL);
    g_return_if_fail(msg != NULL);

    type = ((SteamMsgHdrTrs*) msg->hdr)->type;
    rype = (type & STEAM_MSG_PMASK) ? (type & ~STEAM_MSG_PMASK) : type;
    STEAM_UTIL_DEBUGLN("Reading message %u (0x%0X)", rype, type);
    hndlfunc = steam_util_enum_ptr(enums, NULL, msg->type);

    if (hndlfunc == NULL) {
        STEAM_NET_FUNC(net, message, msg);
        return;
    }

    hndlfunc(net, msg);
}

/**
 * Implemented #b_event_handler for the writing of #SteamNet->fd.
 *
 * @param data The user defined data, which is #SteamNet.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
static gboolean steam_net_cb_write(gpointer data, gint fd,
                                   b_input_condition cond)
{
    SteamNet *net = data;
    gssize    wize;

    wize = write(net->fd, net->wbuf->data, net->wbuf->len);

    if (wize < 0) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Failed to write data");
        return FALSE;
    }

    if (net->wbuf->len > 0) {
        g_byte_array_remove_range(net->wbuf, 0, wize);
        net->wemz -= wize;
    }

    if (net->wemz < 1) {
        net->wev = 0;
        return FALSE;
    }

    return TRUE;
}

/**
 * Writes a #GByteArray to the #SteamNet. This will optionally encrypt
 * the message if required by the #SteamNet.
 *
 * @param net     The #SteamNet.
 * @param bytes   The #GByteArray.
 * @param encrypt TRUE to encrypt the message, otherwise FALSE.
 **/
void steam_net_write(SteamNet *net, const GByteArray *bytes, gboolean encrypt)
{
    GByteArray *cytes;
    guint32     type;
    guint32     rype;
    guint32     size;

    static const guint32 magic = STEAM_MSG_MAGIC;

    g_return_if_fail(net   != NULL);
    g_return_if_fail(bytes != NULL);

    if (bytes->len < sizeof type) {
        steam_net_error(net, STEAM_NET_ERROR_GENERIC, "Invalid message");
        return;
    }

    memcpy(&type, bytes->data, sizeof type);
    rype = (type & STEAM_MSG_PMASK) ? (type & ~STEAM_MSG_PMASK) : type;
    STEAM_UTIL_DEBUGLN("Writing message %u (0x%0X)", rype, type);

    if (encrypt) {
        cytes = steam_crypt_sym_enc(net->skey, bytes);

        if (cytes == NULL) {
            steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                            "Failed to encrypt message");
            return;
        }

        size = cytes->len;
        g_byte_array_append(net->wbuf, (guint8*) &size,  sizeof size);
        g_byte_array_append(net->wbuf, (guint8*) &magic, sizeof magic);
        g_byte_array_append(net->wbuf, cytes->data, cytes->len);
        g_byte_array_free(cytes, TRUE);
    } else {
        size = bytes->len;
        g_byte_array_append(net->wbuf, (guint8*) &size,  sizeof size);
        g_byte_array_append(net->wbuf, (guint8*) &magic, sizeof magic);
        g_byte_array_append(net->wbuf, bytes->data, bytes->len);
    }

    if ((net->wev < 1) && steam_net_cb_write(net, net->fd, B_EV_IO_WRITE))
        net->wev = b_input_add(net->fd, B_EV_IO_WRITE, steam_net_cb_write, net);
}

/**
 * Writes a #SteamMsg to the #SteamNet.
 *
 * @param net The #SteamNet.
 * @param msg The #SteamMsg.
 **/
void steam_net_write_msg(SteamNet *net, const SteamMsg *msg)
{
    GByteArray *bytes;
    guint32     type;
    guint32     rype;

    g_return_if_fail(net != NULL);
    g_return_if_fail(msg != NULL);

    bytes = steam_msg_pack(msg);

    if (bytes == NULL) {
        memcpy(&type, bytes->data, sizeof type);
        rype = (type & STEAM_MSG_PMASK) ? (type & ~STEAM_MSG_PMASK) : type;
        steam_net_error(net, STEAM_NET_ERROR_GENERIC,
                        "Failed to pack message %u (0x%0X)",
                        rype, type);
        return;
    }

    steam_net_write(net, bytes, net->flags & STEAM_NET_FLAG_ENCRYPT);
    g_byte_array_free(bytes, TRUE);
}

/**
 * Sends a logon request.
 *
 * @param net  The #SteamNet.
 * @param user The username.
 * @param pass The password.
 * @param code The authentication code.
 **/
void steam_net_logon(SteamNet *net, const gchar *user, const gchar *pass,
                     const gchar *code)
{
    SteamMsg           *msg;
    CMsgProtoBufHeader *hdr;
    CMsgClientLogon    *csg;
    GChecksum          *csum;
    guint8             *data;
    gsize               size;

    msg = steam_msg_new(STEAM_MSG_TYPE_CLT_LOGON);
    hdr = ((SteamMsgHdrPrt*) msg->hdr)->hdr;
    csg = (CMsgClientLogon*) msg->msg;

    if (net->sentry->len > 0) {
        csum = g_checksum_new(G_CHECKSUM_SHA1);
        size = g_checksum_type_get_length(G_CHECKSUM_SHA1);
        data = g_new(guint8, size);

        g_checksum_update(csum, net->sentry->data, net->sentry->len);
        g_checksum_get_digest(csum, data, &size);
        g_checksum_free(csum);

        csg->eresult_sentryfile  = STEAM_MSG_RLT_TYPE_OK;
        csg->sha_sentryfile.data = data;
        csg->sha_sentryfile.len  = size;
    } else {
        csg->eresult_sentryfile  = STEAM_MSG_RLT_TYPE_NOFILE;
    }

    csg->machine_id.data = g_memdup(net->machid->data, net->machid->len);
    csg->machine_id.len  = net->machid->len;

    hdr->has_client_sessionid = TRUE;
    hdr->client_sessionid     = 0;
    hdr->has_steamid          = TRUE;
    hdr->steamid              = STEAM_ID_NEW(net->univ,
                                             STEAM_ID_TYPE_INDIVIDUAL,
                                             STEAM_ID_INST_DESKTOP, 0);

    csg->has_protocol_version    = TRUE;
    csg->protocol_version        = 65579;
    csg->has_client_package_version = TRUE;
    csg->client_package_version  = 1771;
    csg->client_language         = g_strdup("english");
    csg->has_client_os_type      = TRUE;
    csg->client_os_type          = -203; // LinuxUnknown
    csg->account_name            = g_strdup(user);
    csg->password                = g_strdup(pass);
    csg->auth_code               = g_strdup(code);
    csg->has_steam2_ticket_request = TRUE;
    csg->steam2_ticket_request     = 0;

    steam_net_write_msg(net, msg);
    steam_msg_free(msg);
}
