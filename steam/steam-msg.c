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

#include <string.h>

#include "steam-msg.h"
#include "steam-msgs.h"
#include "steam-user.h"
#include "steam-util.h"

/**
 * Creates a new #SteamMsg. The returned #SteamMsg should be freed with
 * #steam_msg_free() when no longer needed.
 *
 * @param type The #SteamMsgType.
 *
 * @return The #SteamMsg or NULL on error.
 **/
SteamMsg *steam_msg_new(SteamMsgType type)
{
    SteamMsg *msg;

    static const SteamUtilEnum hnums[] = {
        {STEAM_MSG_HDR_TYPE_EXTENDED, (gpointer) &steam_msg_hdr_ext_funcs},
        {STEAM_MSG_HDR_TYPE_PROTOBUF, (gpointer) &steam_msg_hdr_prt_funcs},
        {STEAM_MSG_HDR_TYPE_TERSE,    (gpointer) &steam_msg_hdr_trs_funcs},
        STEAM_UTIL_ENUM_NULL
    };

    static const SteamUtilEnum mnums[] = {
        {STEAM_MSG_TYPE_CHAN_ENC_REQ,  (gpointer) &steam_msg_chan_enc_req_funcs},
        {STEAM_MSG_TYPE_CHAN_ENC_RES,  (gpointer) &steam_msg_chan_enc_res_funcs},
        {STEAM_MSG_TYPE_CHAN_ENC_RLT,  (gpointer) &steam_msg_chan_enc_rlt_funcs},
        {STEAM_MSG_TYPE_CLT_LOGON,     (gpointer) &steam_msg_clt_logon_funcs},
        {STEAM_MSG_TYPE_CLT_LOGON_RES, (gpointer) &steam_msg_clt_logon_res_funcs},
        {STEAM_MSG_TYPE_MUTLI,         (gpointer) &steam_msg_multi_funcs},
        STEAM_UTIL_ENUM_NULL
    };

    msg = g_new0(SteamMsg, 1);
    msg->hype  = steam_msg_hdr_type(type);
    msg->type  = type;
    msg->poad  = g_byte_array_new();
    msg->huncs = steam_util_enum_ptr(hnums, NULL, msg->hype);
    msg->muncs = steam_util_enum_ptr(mnums, NULL, msg->type);

    if (G_UNLIKELY((msg->huncs == NULL) || (msg->muncs == NULL))) {
        steam_msg_free(msg);
        return NULL;
    }

    msg->hdr = msg->huncs->new();
    msg->msg = msg->muncs->new();

    if (G_UNLIKELY((msg->hdr == NULL) || (msg->msg == NULL))) {
        steam_msg_free(msg);
        return NULL;
    }

    /* Typecast safe for now, only the type field is modified */
    ((SteamMsgHdrTrs*) msg->hdr)->type = msg->type;

    return msg;
}

/**
 * Frees all memory used by a #SteamMsg.
 *
 * @param msg The #SteamMsg.
 **/
void steam_msg_free(SteamMsg *msg)
{
    if (G_UNLIKELY(msg == NULL))
        return;

    if ((msg->msg != NULL) && (msg->muncs != NULL))
        msg->muncs->free(msg->msg);

    if ((msg->hdr != NULL) && (msg->huncs != NULL))
        msg->huncs->free(msg->hdr);

    g_byte_array_free(msg->poad, TRUE);
    g_free(msg);
}

/**
 * Packs a #SteamMsg into a data buffer. The returned data buffer should
 * be freed with #g_free() when no longer needed.
 *
 * @param msg The #SteamMsg.
 *
 * @return The data buffer or NULL on error.
 **/
GByteArray *steam_msg_pack(const SteamMsg *msg)
{
    GByteArray *ret;
    GByteArray *tytes;

    g_return_val_if_fail(msg != NULL, NULL);

    tytes = msg->huncs->pack(msg->hdr);

    if (G_UNLIKELY(tytes == NULL))
        return NULL;

    ret = g_byte_array_new();
    g_byte_array_append(ret, tytes->data, tytes->len);
    g_byte_array_free(tytes, TRUE);

    tytes = msg->muncs->pack(msg->msg);

    if (G_UNLIKELY(tytes == NULL)) {
        g_byte_array_free(ret, TRUE);
        return NULL;
    }

    g_byte_array_append(ret, tytes->data, tytes->len);
    g_byte_array_append(ret, msg->poad->data, msg->poad->len);
    g_byte_array_free(tytes, TRUE);

    return ret;
}

/**
 * Creates a new #SteamMsg. This unpacks a #SteamMsg from a data buffer.
 * The returned #SteamMsg should be freed with #steam_msg_free() when no
 * longer needed.
 *
 * @param data The data.
 * @param size The size of the data.
 *
 * @return The #SteamMsg or NULL on error.
 **/
SteamMsg *steam_msg_unpack(const GByteArray *bytes)
{
    SteamMsg   *msg;
    GByteArray *tytes;
    guint32     dype;
    gsize       size;
    gpointer    unpack;

    g_return_val_if_fail(bytes != NULL, NULL);

    if (G_UNLIKELY(sizeof dype > bytes->len))
        return NULL;

    memcpy(&dype, bytes->data, sizeof dype);
    msg = steam_msg_new(dype);

    if (G_UNLIKELY(msg == NULL))
        return NULL;

    msg->hype = steam_msg_hdr_type(dype);
    msg->type = dype;
    unpack = msg->huncs->unpack(bytes);

    if (unpack == NULL) {
        steam_msg_free(msg);
        return NULL;
    }

    msg->huncs->free(msg->hdr);
    msg->hdr = unpack;
    size = msg->huncs->size(msg->hdr);

    tytes = g_byte_array_new();
    g_byte_array_append(tytes, bytes->data + size, bytes->len - size);
    unpack = msg->muncs->unpack(tytes);
    g_byte_array_free(tytes, TRUE);

    if (unpack == NULL) {
        g_byte_array_free(tytes, TRUE);
        steam_msg_free(msg);
        return NULL;
    }

    msg->muncs->free(msg->msg);
    msg->msg = unpack;
    size += msg->muncs->size(msg->msg);

    if (size < bytes->len)
        g_byte_array_append(msg->poad, bytes->data + size, bytes->len - size);

    return msg;
}

/**
 * Determines the #SteamMsgHdrType from the #SteamMsgType.
 *
 * @param type The #SteamMsgType.
 *
 * @return The #SteamMsgHdrType.
 **/
SteamMsgHdrType steam_msg_hdr_type(SteamMsgType type)
{
    switch (type) {
    case STEAM_MSG_TYPE_CHAN_ENC_REQ:
    case STEAM_MSG_TYPE_CHAN_ENC_RES:
    case STEAM_MSG_TYPE_CHAN_ENC_RLT:
        return STEAM_MSG_HDR_TYPE_TERSE;

    default:
        if (type & STEAM_MSG_PMASK)
            return STEAM_MSG_HDR_TYPE_PROTOBUF;

        return STEAM_MSG_HDR_TYPE_EXTENDED;
    }
}

/**
 * Initializes message fields with default values.
 *
 * @param fields The array of #SteamMsgField.
 * @param msg    The message.
 **/
void steam_msg_fields_init(const SteamMsgField *fields, gpointer msg)
{
    gconstpointer val;
    guint         i;

    g_return_if_fail(fields != NULL);
    g_return_if_fail(msg    != NULL);

    for (i = 0; fields[i].size != 0; i++) {
        val = (fields[i].isarr) ? fields[i].defarr : &fields[i].defval;
        memcpy(msg + fields[i].offset, val, fields[i].size);
    }
}

/**
 * Gets the total size of all message fields.
 *
 * @param fields The array of #SteamMsgField.
 *
 * @return The total size.
 **/
gsize steam_msg_fields_size(const SteamMsgField *fields)
{
    gsize size;
    guint i;

    g_return_val_if_fail(fields != NULL, FALSE);

    for (size = i = 0; fields[i].size != 0; i++)
        size += fields[i].size;

    return size;
}

/**
 * Packs message fields from a message into a #GByteArray. The returned
 * #GByteArray should be freed with #g_byte_array_free() when no longer
 * needed.
 *
 * @param fields The array of #SteamMsgField.
 * @param msg    The message.
 *
 * @return The #GByteArray or NULL on error.
 **/
GByteArray *steam_msg_fields_pack(const SteamMsgField *fields,
                                  gconstpointer msg)
{
    GByteArray *ret;
    guint       i;

    g_return_val_if_fail(fields != NULL, FALSE);
    g_return_val_if_fail(msg    != NULL, FALSE);

    ret = g_byte_array_new();

    for (i = 0; fields[i].size != 0; i++)
        g_byte_array_append(ret, msg + fields[i].offset, fields[i].size);

    return ret;
}

/**
 * Unpacks message fields from a #GByteArray into a message.
 *
 * @param fields The array of #SteamMsgField.
 * @param bytes  The #GByteArray.
 * @param msg    The message.
 *
 * @return TRUE if all values were unpacked, otherwise FALSE.
 **/
gboolean steam_msg_fields_unpack(const SteamMsgField *fields,
                                 const GByteArray *bytes,
                                 gpointer msg)
{
    const guint8 *data;
    gsize         size;
    guint         i;

    g_return_val_if_fail(fields != NULL, FALSE);
    g_return_val_if_fail(bytes  != NULL, FALSE);
    g_return_val_if_fail(msg    != NULL, FALSE);

    data = bytes->data;
    size = steam_msg_fields_size(fields);

    if (G_UNLIKELY(size > bytes->len))
        return FALSE;

    for (i = 0; fields[i].size != 0; i++) {
        memcpy(msg + fields[i].offset, data, fields[i].size);
        data += fields[i].size;
    }

    return TRUE;
}
