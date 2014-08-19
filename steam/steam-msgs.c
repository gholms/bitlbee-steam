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

#include "steam-msgs.h"
#include "steam-user.h"


static gpointer steam_protobuf_alloc(gpointer data, gsize size)
{
    return g_malloc(size);
}

static void steam_protobuf_free(gpointer data, gpointer ptr)
{
    g_free(ptr);
}

static ProtobufCAllocator steam_protobuf_allocator = {
	.alloc = &steam_protobuf_alloc,
	.free  = &steam_protobuf_free,
	.allocator_data = NULL
};

/* SteamMsgHdrPrt */
STEAM_MSG_IMPS_FUNCS(steam_msg_hdr_prt);
STEAM_MSG_IMPS_FIELDS(steam_msg_hdr_prt,
    STEAM_MSG_VAL(SteamMsgHdrPrt, type, STEAM_MSG_TYPE_INVALID),
    STEAM_MSG_VAL(SteamMsgHdrPrt, size, 0)
);

SteamMsgHdrPrt *steam_msg_hdr_prt_new(void)
{
    SteamMsgHdrPrt *msg;

    msg = g_new0(SteamMsgHdrPrt, 1);
    steam_msg_fields_init(steam_msg_hdr_prt_fields, msg);

    msg->hdr = g_new0(CMsgProtoBufHeader, 1);
    cmsg_proto_buf_header__init(msg->hdr);

    return msg;
}

void steam_msg_hdr_prt_free(SteamMsgHdrPrt *msg)
{
    if (G_UNLIKELY(msg == NULL))
        return;

    if (G_LIKELY(msg->hdr != NULL))
        cmsg_proto_buf_header__free_unpacked(msg->hdr, NULL);

    g_free(msg);
}

gsize steam_msg_hdr_prt_size(const SteamMsgHdrPrt *msg)
{
    gsize size;

    g_return_val_if_fail(msg != NULL, 0);

    size  = steam_msg_fields_size(steam_msg_hdr_prt_fields);
    size += cmsg_proto_buf_header__get_packed_size(msg->hdr);

    return size;
}

GByteArray *steam_msg_hdr_prt_pack(const SteamMsgHdrPrt *msg)
{
    GByteArray     *ret;
    SteamMsgHdrPrt  hdr;
    gsize           size;
    gsize           rize;

    memcpy(&hdr, msg, sizeof hdr);
    hdr.size = cmsg_proto_buf_header__get_packed_size(msg->hdr);;
    ret = steam_msg_fields_pack(steam_msg_hdr_prt_fields, &hdr);

    if (ret == NULL)
        return NULL;

    size = ret->len;
    g_byte_array_set_size(ret, ret->len + hdr.size);
    rize = cmsg_proto_buf_header__pack(msg->hdr, ret->data + size);

    g_warn_if_fail(rize <= hdr.size);
    g_byte_array_set_size(ret, size + rize);

    return ret;
}

SteamMsgHdrPrt *steam_msg_hdr_prt_unpack(const GByteArray *bytes)
{
    SteamMsgHdrPrt *msg;
    gsize           size;

    msg  = steam_msg_hdr_prt_new();
    size = steam_msg_fields_size(steam_msg_hdr_prt_fields);

    if (!steam_msg_fields_unpack(steam_msg_hdr_prt_fields, bytes, msg) ||
        (bytes->len < (msg->size + size)))
    {
        steam_msg_hdr_prt_free(msg);
        return NULL;
    }

    msg->hdr = cmsg_proto_buf_header__unpack(NULL, msg->size,
                                             bytes->data + size);

    if (msg->hdr == NULL) {
        steam_msg_hdr_prt_free(msg);
        return NULL;
    }

    return msg;
}

/* SteamMsgHdrExt */
STEAM_MSG_IMPS(SteamMsgHdrExt, steam_msg_hdr_ext,
    STEAM_MSG_VAL(SteamMsgHdrExt, type,    STEAM_MSG_TYPE_INVALID),
    STEAM_MSG_VAL(SteamMsgHdrExt, size,    36),
    STEAM_MSG_VAL(SteamMsgHdrExt, vers,    2),
    STEAM_MSG_VAL(SteamMsgHdrExt, tjid,    G_MAXUINT64),
    STEAM_MSG_VAL(SteamMsgHdrExt, sjid,    G_MAXUINT64),
    STEAM_MSG_VAL(SteamMsgHdrExt, cnry,    239),
    STEAM_MSG_VAL(SteamMsgHdrExt, steamid, 0),
    STEAM_MSG_VAL(SteamMsgHdrExt, sessid,  0)
);

/* SteamMsgHdrTrs */
STEAM_MSG_IMPS(SteamMsgHdrTrs, steam_msg_hdr_trs,
    STEAM_MSG_VAL(SteamMsgHdrTrs, type, STEAM_MSG_TYPE_INVALID),
    STEAM_MSG_VAL(SteamMsgHdrTrs, tjid, G_MAXUINT64),
    STEAM_MSG_VAL(SteamMsgHdrTrs, sjid, G_MAXUINT64)
);

/* SteamMsgChanEncReq */
STEAM_MSG_IMPS(SteamMsgChanEncReq, steam_msg_chan_enc_req,
    STEAM_MSG_VAL(SteamMsgChanEncReq, vers, 1),
    STEAM_MSG_VAL(SteamMsgChanEncReq, univ, STEAM_ID_UNIV_UNKNOWN)
);

/* SteamMsgChanEncRes */
STEAM_MSG_IMPS(SteamMsgChanEncRes, steam_msg_chan_enc_res,
    STEAM_MSG_VAL(SteamMsgChanEncRes, vers, 1),
    STEAM_MSG_VAL(SteamMsgChanEncRes, kize, 128)
);

/* SteamMsgChanEncRlt */
STEAM_MSG_IMPS(SteamMsgChanEncRlt, steam_msg_chan_enc_rlt,
    STEAM_MSG_VAL(SteamMsgChanEncRlt, rlt, 0)
);

/* CMsgClientLogon */
STEAM_MSG_IMPS_PROTO(CMsgClientLogon, steam_msg_clt_logon, cmsg_client_logon,
                     steam_protobuf_allocator);

/* CMsgClientLogonResponse */
STEAM_MSG_IMPS_PROTO(CMsgClientLogonResponse, steam_msg_clt_logon_res,
                     cmsg_client_logon_response, steam_protobuf_allocator);

/* CMsgMulti */
STEAM_MSG_IMPS_PROTO(CMsgMulti, steam_msg_multi, cmsg_multi,
                     steam_protobuf_allocator);
