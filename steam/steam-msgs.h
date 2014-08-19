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

/** @file **/

#ifndef _STEAM_MSGS_H
#define _STEAM_MSGS_H

#include <glib.h>

#include "steam-msg.h"

/* SteamMsgHdrExt */
STEAM_MSG_DEFS(SteamMsgHdrExt, steam_msg_hdr_ext,
    guint32 type;
    guint8  size;
    guint16 vers;
    guint64 tjid;
    guint64 sjid;
    guint8  cnry;
    guint64 steamid;
    guint32 sessid;
);

/* SteamMsgHdrPrt */
STEAM_MSG_DEFS(SteamMsgHdrPrt, steam_msg_hdr_prt,
    guint32 type;
    guint32 size;
    CMsgProtoBufHeader *hdr;
);

/* SteamMsgHdrTrs */
STEAM_MSG_DEFS(SteamMsgHdrTrs, steam_msg_hdr_trs,
    guint32 type;
    guint64 tjid;
    guint64 sjid;
);

/* SteamMsgChanEncReq */
STEAM_MSG_DEFS(SteamMsgChanEncReq, steam_msg_chan_enc_req,
    guint32 vers;
    guint32 univ;
);

/* SteamMsgChanEncRes */
STEAM_MSG_DEFS(SteamMsgChanEncRes, steam_msg_chan_enc_res,
    guint32 vers;
    guint32 kize;
);

/* SteamMsgChanEncRlt */
STEAM_MSG_DEFS(SteamMsgChanEncRlt, steam_msg_chan_enc_rlt,
    guint32 rlt;
);

/* Protobufs */
STEAM_MSG_DEFS_FUNCS(CMsgClientLogon,         steam_msg_clt_logon);
STEAM_MSG_DEFS_FUNCS(CMsgClientLogonResponse, steam_msg_clt_logon_res);
STEAM_MSG_DEFS_FUNCS(CMsgMulti,               steam_msg_multi);

#endif /* _STEAM_MSGS_H */
