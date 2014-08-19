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

#ifndef _STEAM_MSG_H
#define _STEAM_MSG_H

#include <bitlbee.h>
#include <glib.h>

#include "steam.pb-c.h"
#include "steam-util.h"

#define STEAM_MSG_MAGIC 0x31305456
#define STEAM_MSG_PMASK 0x80000000

/**
 * Implements the fields variable used for a message type.
 *
 * @param p   The message type prefix.
 * @param ... The list of #SteamMsgField.
 **/
#define STEAM_MSG_IMPS_FIELDS(p, ...)           \
    static const SteamMsgField p##_fields[] = { \
            __VA_ARGS__,                        \
            STEAM_MSG_FIELD_NULL                \
    };

/**
 * Implements the funcs variable used for a message type.
 *
 * @param p The message type prefix.
 **/
#define STEAM_MSG_IMPS_FUNCS(p)                                 \
    const SteamMsgFuncs p##_funcs = {                           \
        .new    = (gpointer (*) (void)) p##_new,                \
        .free   = (void (*) (gpointer)) p##_free,               \
        .size   = (gsize (*) (gconstpointer)) p##_size,         \
        .pack   = (GByteArray *(*) (gconstpointer)) p##_pack,   \
        .unpack = (gpointer (*) (const GByteArray*)) p##_unpack \
    };

/**
 * Implements the functions and variables used for a message type.
 *
 * @param t   The message type.
 * @param p   The message type prefix.
 * @param ... The list of #SteamMsgField.
 **/
#define STEAM_MSG_IMPS(t, p, ...)                               \
    STEAM_MSG_IMPS_FIELDS(p, __VA_ARGS__);                      \
    STEAM_MSG_IMPS_FUNCS(p);                                    \
    t *p##_new(void) {                                          \
        t *msg = g_new0(t, 1);                                  \
        steam_msg_fields_init(p##_fields, msg);                 \
        return msg;                                             \
    }                                                           \
    void p##_free(t *msg) {                                     \
        g_free(msg);                                            \
    }                                                           \
    gsize p##_size(const t *msg) {                              \
        return steam_msg_fields_size(p##_fields);               \
    }                                                           \
    GByteArray *p##_pack(const t *msg) {                        \
        return steam_msg_fields_pack(p##_fields, msg);          \
    }                                                           \
    t *p##_unpack(const GByteArray *bytes) {                    \
        t *msg = p##_new();                                     \
        if (!steam_msg_fields_unpack(p##_fields, bytes, msg)) { \
            p##_free(msg);                                      \
            return NULL;                                        \
        }                                                       \
        return msg;                                             \
    }

/**
 * Implements the functions and variables used for a message type which
 * is protobuf based.
 *
 * @param t  The message type.
 * @param p  The message type prefix.
 * @param pp The protobuf prefix.
 * @param a  The #ProtobufCAllocator.
 **/
#define STEAM_MSG_IMPS_PROTO(t, p, pp, a)                 \
    STEAM_MSG_IMPS_FUNCS(p);                              \
    t *p##_new(void) {                                    \
        t *msg = a.alloc(a.allocator_data, sizeof (t));   \
        pp##__init(msg);                                  \
        return msg;                                       \
    }                                                     \
    void p##_free(t *msg) {                               \
        if (G_LIKELY(msg != NULL)) {                      \
            pp##__free_unpacked(msg, &a);                 \
        }                                                 \
    }                                                     \
    gsize p##_size(const t *msg) {                        \
        g_return_val_if_fail(msg != NULL, 0);             \
        return pp##__get_packed_size(msg);                \
    }                                                     \
    GByteArray *p##_pack(const t *msg) {                  \
        g_return_val_if_fail(msg != NULL, NULL);          \
        gsize size = p##_size(msg);                       \
        GByteArray *ret = g_byte_array_new();             \
        g_byte_array_set_size(ret, size);                 \
        size = pp##__pack(msg, ret->data);                \
        g_warn_if_fail(size <= ret->len);                 \
        g_byte_array_set_size(ret, size);                 \
        return ret;                                       \
    }                                                     \
    t *p##_unpack(const GByteArray *bytes) {              \
        g_return_val_if_fail(bytes != NULL, NULL);        \
        return pp##__unpack(&a, bytes->len, bytes->data); \
    }

/**
 * Defines the functions used for a message type.
 *
 * @param t The message type.
 * @param p The message type prefix.
 **/
#define STEAM_MSG_DEFS_FUNCS(t, p)          \
    t *p##_new(void);                       \
    void p##_free(t *msg);                  \
    gsize p##_size(const t *msg);           \
    GByteArray *p##_pack(const t *msg);     \
    t *p##_unpack(const GByteArray *bytes); \
    extern const SteamMsgFuncs p##_funcs;

/**
 * Defines the functions and type used for a message type.
 *
 * @param t   The message type.
 * @param p   The message type prefix.
 * @param ... The list of structure elements.
 **/
#define STEAM_MSG_DEFS(t, p, ...) \
    typedef struct _##t t;        \
    struct _##t {__VA_ARGS__} ;   \
    STEAM_MSG_DEFS_FUNCS(t, p);

/**
 * Initializes a SteamMsgField for an array.
 *
 * @param t The message type.
 * @param f The field name.
 * @param a The default array.
 **/
#define STEAM_MSG_ARR(t, f, a) {                       \
        .offset = G_STRUCT_OFFSET(t, f),               \
        .size   = STEAM_UTIL_ARR_SIZE(((t*) NULL)->f), \
        .isarr  = TRUE,                                \
        .defarr = a,                                   \
        .defval = 0                                    \
    }

/**
 * Initializes a SteamMsgField for a value.
 *
 * @param t The message type.
 * @param f The field name.
 * @param p The default pointer.
 **/
#define STEAM_MSG_VAL(t, f, v) {         \
        .offset = G_STRUCT_OFFSET(t, f), \
        .size   = sizeof ((t*) NULL)->f, \
        .isarr  = FALSE,                 \
        .defarr = NULL,                  \
        .defval = v                      \
    }

#define STEAM_MSG_FIELD_NULL {0, 0, 0, NULL, 0}


/** The types of Steam messages. **/
typedef enum _SteamMsgType SteamMsgType;

/** The types of Steam message results. **/
typedef enum _SteamMsgRltType SteamMsgRltType;

/** The types of Steam message headers. **/
typedef enum _SteamMsgHdrType SteamMsgHdrType;

/** The main structure for Steam messages. **/
typedef struct _SteamMsg SteamMsg;

/** The structure for holding data field information. **/
typedef struct _SteamMsgField SteamMsgField;

/** The structure for holding the #SteamMsg functions. **/
typedef struct _SteamMsgFuncs SteamMsgFuncs;


/**
 * The types of Steam messages.
 **/
enum _SteamMsgType
{
    /** Invalid **/
    STEAM_MSG_TYPE_INVALID       = 0,

    /** Multiple **/
    STEAM_MSG_TYPE_MUTLI         = 1    | STEAM_MSG_PMASK,

    /** Channel Encrypt Request **/
    STEAM_MSG_TYPE_CHAN_ENC_REQ  = 1303,

    /** Channel Encrypt Response **/
    STEAM_MSG_TYPE_CHAN_ENC_RES  = 1304,

    /** Channel Encrypt Result **/
    STEAM_MSG_TYPE_CHAN_ENC_RLT  = 1305,

    /** Client logon **/
    STEAM_MSG_TYPE_CLT_LOGON     = 5514 | STEAM_MSG_PMASK,

    /** Client logon response **/
    STEAM_MSG_TYPE_CLT_LOGON_RES = 751  | STEAM_MSG_PMASK,
};

/**
 * The types of Steam message results.
 **/
enum _SteamMsgRltType
{
    STEAM_MSG_RLT_TYPE_INVALID = 0, /** Invalid **/
    STEAM_MSG_RLT_TYPE_OK      = 1, /** OK **/
    STEAM_MSG_RLT_TYPE_FAIL    = 2, /** Fail **/
    STEAM_MSG_RLT_TYPE_NOFILE  = 9  /** File not found **/
};

/**
 * The types of Steam message headers.
 **/
enum _SteamMsgHdrType
{
    STEAM_MSG_HDR_TYPE_EXTENDED, /** Extended **/
    STEAM_MSG_HDR_TYPE_PROTOBUF, /** Protobuf **/
    STEAM_MSG_HDR_TYPE_TERSE     /** Terse **/
};

/**
 * The main structure for Steam messages.
 **/
struct _SteamMsg
{
    SteamMsgHdrType  hype;      /** The #SteamMsgHdrType. **/
    SteamMsgType     type;      /** The #SteamMsgType. **/
    GByteArray      *poad;      /** The payload. **/

    gpointer hdr;               /** The header. **/
    gpointer msg;               /** The message. **/

    const SteamMsgFuncs *huncs; /** The header #SteamMsgFuncs. **/
    const SteamMsgFuncs *muncs; /** The message #SteamMsgFuncs. **/
};

/**
 * The structure for holding data field information.
 **/
struct _SteamMsgField
{
    gsize    offset; /** The offset. **/
    gsize    size;   /** The size. **/
    gboolean isarr;  /** The array status. **/
    gpointer defarr; /** The default array. **/
    guint64  defval; /** The default value. **/
};

/**
 * The structure for holding the #SteamMsg functions.
 **/
struct _SteamMsgFuncs
{
    gpointer    (*new)    (void);                    /** The creator. **/
    void        (*free)   (gpointer msg);            /** The freer. **/
    gsize       (*size)   (gconstpointer msg);       /** The sizer. **/
    GByteArray *(*pack)   (gconstpointer msg);       /** The packer. **/
    gpointer    (*unpack) (const GByteArray *bytes); /** The unpacker. **/
};


SteamMsg *steam_msg_new(SteamMsgType type);

void steam_msg_free(SteamMsg *msg);

GByteArray *steam_msg_pack(const SteamMsg *msg);

SteamMsg *steam_msg_unpack(const GByteArray *bytes);

SteamMsgHdrType steam_msg_hdr_type(SteamMsgType type);

void steam_msg_fields_init(const SteamMsgField *fields, gpointer msg);

gsize steam_msg_fields_size(const SteamMsgField *fields);

GByteArray *steam_msg_fields_pack(const SteamMsgField *fields,
                                  gconstpointer msg);

gboolean steam_msg_fields_unpack(const SteamMsgField *fields,
                                 const GByteArray *bytes,
                                 gpointer msg);

#endif /* _STEAM_MSG_H */
