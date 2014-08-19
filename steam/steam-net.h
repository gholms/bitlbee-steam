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

#ifndef _STEAM_NET_H
#define _STEAM_NET_H

#include <bitlbee.h>
#include <glib.h>

#include "steam-msg.h"
#include "steam-user.h"

#define STEAM_NET_TIMEOUT 5000

/**
 * Executes one of the #SteamNetFuncs.
 *
 * @param n   The #SteamNet.
 * @param f   The function to execute.
 * @param ... The operational function arguments.
 **/
#define STEAM_NET_FUNC(n, f, ...)            \
    G_STMT_START {                           \
        if (G_LIKELY(n->funcs->f != NULL)) { \
            n->funcs->f(n, ##__VA_ARGS__);   \
        }                                    \
    } G_STMT_END

#define STEAM_NET_ERROR steam_net_error_quark()


/** The #GError codes of #SteamNet. **/
typedef enum _SteamNetError SteamNetError;

/** The flags of a #SteamNet. **/
typedef enum _SteamNetFlags SteamNetFlags;

/** The main structure for Steam networking. **/
typedef struct _SteamNet SteamNet;

/** The main structure for Steam networking events. **/
typedef struct _SteamNetEvt SteamNetEvt;

/** The main structure for #SteamNet callback functions. **/
typedef struct _SteamNetFuncs SteamNetFuncs;

/** The structure for representing a hostname:port. **/
typedef struct _SteamNetHost SteamNetHost;


/**
 * The #GError codes of #SteamNet.
 **/
enum _SteamNetError
{
    STEAM_NET_ERROR_GENERIC /** generic **/
};

/**
 * The flags of a #SteamNet.
 **/
enum _SteamNetFlags
{
    STEAM_NET_FLAG_ENCRYPT = 1 << 0 /** Encrypt **/
};

/**
 * The main structure for Steam networking.
 **/
struct _SteamNet
{
    SteamNetFlags  flags; /** The #SteamNetFlags. **/
    SteamNetEvt   *cevt;  /** The #SteamNetEvt. **/
    SteamNetFuncs *funcs; /** The #SteamNetFuncs. **/
    gpointer       data;  /** The user defined data or NULL. **/

    SteamIdUniv univ;     /** The #SteamIdUniv. **/

    GByteArray *skey;     /** The session key. **/
    GByteArray *machid;   /** The machine identifier. **/
    GByteArray *sentry;   /** The sentry data. **/

    GByteArray *rbuf;     /** The read buffer. **/
    gsize       remz;     /** The remaining read size. **/
    GByteArray *wbuf;     /** The write buffer. **/
    gsize       wemz;     /** The remaining write size. **/

    gint fd;              /** The connection file descriptor. **/
    gint tev;             /** The timer event identifier. **/
    gint rev;             /** The read event identifier. **/
    gint wev;             /** The write event identifier. **/

    GError *err;          /** The #GError or NULL. **/
};

/**
 * The main structure for Steam networking events.
 **/
struct _SteamNetEvt
{
    SteamNet *net;        /** The #SteamNet.**/
    b_event_handler func; /** The #b_event_handler. **/
};

/**
 * The main structure for #SteamNet callback functions.
 **/
struct _SteamNetFuncs
{
    /** The error function. **/
    void (*error)     (SteamNet *net);

    /** The connected function. **/
    void (*connected) (SteamNet *net);

    /** The message function. **/
    void (*message)   (SteamNet *net, const SteamMsg *msg);
};

/**
 * The structure for representing a hostname:port.
 **/
struct _SteamNetHost
{
    const gchar *name; /** The hostname or address. **/
    gint         port; /** The port number. **/
};


GQuark steam_net_error_quark(void);

SteamNet *steam_net_new(const SteamNetFuncs *funcs, gpointer data);

void steam_net_free(SteamNet *net);

void steam_net_close(SteamNet *net);

SteamNetEvt *steam_net_evt_new(SteamNet *net, b_event_handler func);

void steam_net_evt_free(SteamNetEvt *evt);

gboolean steam_net_evt_exec(gpointer data, gint fd, b_input_condition cond);

void steam_net_connect(SteamNet *net, const gchar *host, gint port);

void steam_net_connect_rand(SteamNet *net);

gboolean steam_net_connected(SteamNet *net, gboolean error);

void steam_net_read(SteamNet *net, const GByteArray *bytes, gboolean decrypt);

void steam_net_read_msg(SteamNet *net, const SteamMsg *msg);

void steam_net_write(SteamNet *net, const GByteArray *bytes, gboolean encrypt);

void steam_net_write_msg(SteamNet *net, const SteamMsg *msg);

void steam_net_logon(SteamNet *net, const gchar *user, const gchar *pass,
                     const gchar *code);

#endif /* _STEAM_NET_H */
