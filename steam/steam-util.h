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

#ifndef _STEAM_UTIL_H
#define _STEAM_UTIL_H

#include <glib.h>

/**
 * Prints a debugging line to stdout.
 *
 * @param f   The format string literal.
 * @param ... The arguments for the format string.
 **/
#ifdef DEBUG_STEAM
#define STEAM_UTIL_DEBUGLN(f, ...)                                \
    G_STMT_START {                                                \
        if (steam_util_debugging()) {                             \
            g_print("[" PACKAGE_NAME "] " f "\n", ##__VA_ARGS__); \
        }                                                         \
    } G_STMT_END
#else /* DEBUG_STEAM */
#define STEAM_UTIL_DEBUGLN(f, ...)
#endif /* DEBUG_STEAM */

#define STEAM_UTIL_ARR_SIZE(arr) (G_N_ELEMENTS(arr) * sizeof arr[0])
#define STEAM_UTIL_ENUM_NULL     {0, NULL}


/** The structure for holding value/pointer pairs for enumerators. **/
typedef struct _SteamUtilEnum SteamUtilEnum;

/** The structure for holding name/span pairs for time spans. **/
typedef struct _SteamUtilTimeSpan SteamUtilTimeSpan;


/**
 * The structure for holding value/pointer pairs for enumerators.
 **/
struct _SteamUtilEnum
{
    guint    val; /** The value. **/
    gpointer ptr; /** The pointer. **/
};

/**
 * The structure for holding name/span pairs for time spans.
 **/
struct _SteamUtilTimeSpan
{
    gchar  *name; /** The name. **/
    gint64  span; /** The span. **/
};


#ifdef DEBUG_STEAM
gboolean steam_util_debugging(void);
#endif /* DEBUG_STEAM */

GByteArray *steam_util_bytes_base64_dec(const gchar *base64);

gchar *steam_util_bytes_base64_enc(const GByteArray *bytes);

GByteArray *steam_util_bytes_xor(const GByteArray *b1, const GByteArray *b2);

gpointer steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def,
                             guint val);

gpointer *steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals);

guint steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                          gconstpointer ptr, GCompareFunc cmpfunc);

GByteArray *steam_util_gzip_def(const GByteArray *bytes);

GByteArray *steam_util_gzip_inf(const GByteArray *bytes, gsize size);

gchar *steam_util_time_span_str(GTimeSpan span);

gchar *steam_util_time_since_utc(gint64 timestamp);

#endif /* _STEAM_UTIL_H */
