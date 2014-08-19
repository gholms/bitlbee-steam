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
#include <zlib.h>

#include "steam-util.h"

/**
 * Determines the debugging state of the plugin.
 *
 * @return TRUE if debugging is enabled, otherwise FALSE.
 **/
#ifdef DEBUG_STEAM
gboolean steam_util_debugging(void)
{
    static gboolean debug = FALSE;
    static gboolean setup = FALSE;

    if (G_UNLIKELY(!setup)) {
        debug = g_getenv("BITLBEE_DEBUG") || g_getenv("BITLBEE_DEBUG_STEAM");
        setup = TRUE;
    }

    return debug;
}
#endif /* DEBUG_STEAM */

/**
 * Decodes a #GByteArray with base64 encoding. The returned #GByteArray
 * should be freed with #g_byte_array_free() when no longer needed.
 *
 * @param bytes The base64 encoded string.
 *
 * @return The #GByteArray, or NULL on error.
 **/
GByteArray *steam_util_bytes_base64_dec(const gchar *base64)
{
    GByteArray *ret;
    guint8     *data;
    gsize       size;

    g_return_val_if_fail(base64 != NULL, NULL);

    ret  = g_byte_array_new();
    data = g_base64_decode(base64, &size);
    g_byte_array_append(ret, data, size);

    return ret;
}

/**
 * Encodes a #GByteArray with base64 encoding. The returned string
 * should be freed with #g_free() when no longer needed.
 *
 * @param bytes The #GByteArray.
 *
 * @return The base64 encoded string, or NULL on error.
 **/
gchar *steam_util_bytes_base64_enc(const GByteArray *bytes)
{
    g_return_val_if_fail(bytes != NULL, NULL);

    if (bytes->len < 1)
        return NULL;

    return g_base64_encode(bytes->data, bytes->len);
}

/**
 * XORs two #GByteArrays. The returned #GByteArray should be freed with
 * #g_byte_array_free() when no longer needed.
 *
 * @param b1 The first #GByteArray.
 * @param b2 The second #GByteArray.
 *
 * @return The XORed #GByteArray or NULL on error.
 **/
GByteArray *steam_util_bytes_xor(const GByteArray *b1, const GByteArray *b2)
{
    GByteArray *ret;
    gsize       size;
    guint       i;

    g_return_val_if_fail(b1 != NULL, NULL);
    g_return_val_if_fail(b2 != NULL, NULL);

    ret  = g_byte_array_new();
    size = MIN(b1->len, b2->len);
    g_byte_array_set_size(ret, size);

    for (i = 0; i < size; i++)
        ret->data[i] = b1->data[i] ^ b2->data[i];

    return ret;
}

/**
 * Gets the enumerator pointer from its value.
 *
 * @param enums The array of #SteamUtilEnum.
 * @param def   The default return value.
 * @param val   The enumerator value.
 *
 * @return The enumerator pointer, or NULL on error.
 **/
gpointer steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def,
                             guint val)
{
    guint i;

    g_return_val_if_fail(enums != NULL, NULL);

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (enums[i].val == val)
            return enums[i].ptr;
    }

    return def;
}

/**
 * Gets the enumerator pointers from its value. The returned array
 * should be freed when no longer needed.
 *
 * @param enums The array of #SteamUtilEnum.
 * @param vals  The enumerator values.
 *
 * @return The enumerator pointer array.
 **/
gpointer *steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals)
{
    gpointer *ptrs;
    gsize     size;
    guint     i;
    guint     j;

    g_return_val_if_fail(enums != NULL, g_new0(gpointer, 0));

    for (size = 0, i = 0; enums[i].ptr != NULL; i++) {
        if (vals & enums[i].val)
            size++;
    }

    ptrs = g_new0(gpointer, ++size);

    for (i = 0, j = 0; enums[i].ptr != NULL; i++) {
        if (vals & enums[i].val)
            ptrs[j++] = enums[i].ptr;
    }

    return ptrs;
}

/**
 * Gets the enumerator value from its pointer.
 *
 * @param enums   The array of #SteamUtilEnum.
 * @param ptr     The enumerator pointer.
 * @param def     The default return value.
 * @param cmpfunc The #GCompareFunc.
 *
 * @return The enumerator value, or 0 on error.
 **/
guint steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                          gconstpointer ptr, GCompareFunc cmpfunc)
{
    guint i;

    g_return_val_if_fail(enums   != NULL, 0);
    g_return_val_if_fail(ptr     != NULL, 0);
    g_return_val_if_fail(cmpfunc != NULL, 0);

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (cmpfunc(ptr, enums[i].ptr) == 0)
            return enums[i].val;
    }

    return def;
}

/**
 * Deflates a #GByteArray. The returned #GByteArray should be freed with
 * #g_byte_array_free() when no longer needed.
 *
 * @param bytes The #GByteArray.
 *
 * @return The deflated #GByteArray, or NULL on error.
 **/
GByteArray *steam_util_gzip_def(const GByteArray *bytes)
{
    GByteArray *ret;
    gsize       rize;
    gint        res;

    ret  = g_byte_array_new();
    rize = compressBound(bytes->len);

    g_byte_array_set_size(ret, rize);
    res = compress(ret->data, &rize, bytes->data, bytes->len);

    if (res != Z_OK) {
        g_byte_array_free(ret, TRUE);
        return NULL;
    }

    g_warn_if_fail(rize <= ret->len);
    g_byte_array_set_size(ret, rize);

    return ret;
}

/**
 * Inflates a #GByteArray. The returned #GByteArray should be freed with
 * #g_byte_array_free() when no longer needed.
 *
 * @param bytes The #GByteArray.
 * @param size  The inflated size.
 *
 * @return The inflated #GByteArray, or NULL on error.
 **/
GByteArray *steam_util_gzip_inf(const GByteArray *bytes, gsize size)
{
    GByteArray *ret;
    gsize       rize;
    gint        res;

    ret = g_byte_array_new();
    g_byte_array_set_size(ret, size);

    rize = ret->len;
    res  = uncompress(ret->data, &rize, bytes->data, bytes->len);

    if (res != Z_OK) {
        g_byte_array_free(ret, TRUE);
        return NULL;
    }

    g_warn_if_fail(rize <= ret->len);
    g_byte_array_set_size(ret, rize);

    return ret;
}

/**
 * Gets the string representation of a timespan. The returned string
 * should be freed with #g_free() when no longer needed.
 *
 * @param span The #GTimeSpan.
 *
 * @return The string representation of a timespan.
 **/
gchar *steam_util_time_span_str(GTimeSpan span)
{
    gchar *str;
    guint  i;

    static const SteamUtilTimeSpan spans[] = {
        {"second", 1},
        {"minute", 60},
        {"hour",   60 * 60},
        {"day",    60 * 60 * 24},
        {"week",   60 * 60 * 24 * 7},
        {"month",  60 * 60 * 24 * 30},
        {"year",   60 * 60 * 24 * 365},
        {NULL, 0}
    };

    span /= G_TIME_SPAN_SECOND;

    for (i = 1; spans[i].name != NULL; i++) {
        if (span < spans[i].span) {
            span /= spans[--i].span;
            break;
        }

        if (G_UNLIKELY(spans[i + 1].name == NULL)) {
            span /= spans[i].span;
            break;
        }
    }

    str = g_strdup_printf("%" G_GINT64_FORMAT " %s%s", span, spans[i].name,
                          ((span > 1) ? "s" : ""));

    return str;
}

/**
 * Gets the string representation of a timespan since the given
 * timestamp. The returned string should be freed with #g_free() when
 * no longer needed.
 *
 * @param span The timestamp (UTC).
 *
 * @return The string representation of a timespan.
 **/
gchar *steam_util_time_since_utc(gint64 timestamp)
{
    GDateTime *beg;
    GDateTime *end;
    GTimeSpan  spn;

    beg = g_date_time_new_from_unix_utc(timestamp);
    end = g_date_time_new_now_utc();
    spn = g_date_time_difference(end, beg);

    g_date_time_unref(beg);
    g_date_time_unref(end);

    if (G_UNLIKELY(spn < 0))
        spn = -spn;

    return steam_util_time_span_str(spn);
}
