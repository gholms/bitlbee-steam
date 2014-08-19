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

#include <bitlbee.h>
#include <gcrypt.h>
#include <string.h>

#include "steam-crypt.h"
#include "steam-util.h"

/**
 * Calculates the CRC32 hash of a #GByteArray.
 *
 * @param bytes The #GByteArray.
 *
 * @return The CRC32 hash or 0 on error.
 **/
guint32 steam_crypt_crc32(const GByteArray *bytes)
{
    guint32 r;
    guint   i;
    guint   j;

    static guint32 table[256] = {0, 0};

    g_return_val_if_fail(bytes != NULL, 0);

    if (G_UNLIKELY(table[1] == 0)) {
        for (i = 0; i < G_N_ELEMENTS(table); i++) {
            for (r = i, j = 0; j < 8; j++)
                r = (r & 1) ? (0xEDB88320 ^ (r >> 1)) : (r >> 1);

            table[i] = r;
        }
    }

    for (r = G_MAXUINT32, i = 0; i < bytes->len; i++)
        r = table[(bytes->data[i] ^ r) & 0xFF] ^ (r >> 8);

    return r ^ G_MAXUINT32;
}

/**
 * Extracts the integer values, the modulus and the exponent, from an
 * RSA public key.
 *
 * @param key The key #GByteArray.
 * @param mod The return location for the modulus #gcry_mpi_t.
 * @param exp The return location for the exponent #gcry_mpi_t.
 *
 * @return TRUE if the integers were extracted, otherwise FALSE.
 **/
static gboolean steam_crypt_rsa_ints(const GByteArray *key, gcry_mpi_t *mod,
                                     gcry_mpi_t *exp)
{
    const guint8 *data;
    const guint8 *tail;
    guint8        byte;
    guint8        lyte;
    gsize         size;
    guint         d;
    guint         i;
    guint         j;

    static const guint8 ptns[] = {
        0x30, 0x30, 0x06, 0xFF, 0x03, 0x30, 0x02, 0x02
    };

    /* One for each 0x02 */
    const guint8 *datas[2];
    gsize         sizes[2];

    data = key->data;
    tail = key->data + key->len;

    for (d = i = 0; i < G_N_ELEMENTS(ptns); i++) {
        if (((data + 2) > tail) || ((data[0] != ptns[i]) && (ptns[i] != 0xFF)))
            return FALSE;

        byte = (data++)[0];

        if (ptns[i] != 0xFF) {
            lyte = (data++)[0];
            size = lyte & 0x7F;
        } else {
            lyte = 0;
            size = 0;
        }

        if (size != lyte) {
            if ((size > 4) || ((data + size) > tail))
                return FALSE;

            for (j = size, size = 0; j > 0; j--)
                size = (size << 8) | (data++)[0];
        }

        if ((byte == 0x03) || (byte == 0x05)) {
            if (data[0] != 0x00)
                return FALSE;

            size = 1;
        }

        if (byte == 0x02) {
            datas[d]   = data;
            sizes[d++] = size;
        }

        if (((byte >= 0x02) && (byte <= 0x06)) || (ptns[i] == 0xFF))
            data += size;
    }

    gcry_mpi_scan(mod, GCRYMPI_FMT_STD, datas[0], sizes[0], NULL);
    gcry_mpi_scan(exp, GCRYMPI_FMT_STD, datas[1], sizes[1], NULL);
    return TRUE;
}

/**
 * Encrypts a #GByteArray via an RSA public key modules and exponent.
 * The returned #GByteArray should be freed with #g_byte_array_free()
 * when no longer needed.
 *
 * @param key   The key.
 * @param bytes The #GByteArray.
 *
 * @return The encrypted #GByteArray or NULL on error.
 **/
GByteArray *steam_crypt_rsa_enc(const GByteArray *key, const GByteArray *bytes)
{
    GByteArray   *ret;
    gcry_mpi_t    mmpi;
    gcry_mpi_t    empi;
    gcry_mpi_t    dmpi;
    gcry_sexp_t   kata;
    gcry_sexp_t   data;
    gcry_sexp_t   cata;
    gcry_error_t  res;
    gsize         kize;
    gsize         size;

    g_return_val_if_fail(key   != NULL, NULL);
    g_return_val_if_fail(bytes != NULL, NULL);

    if (!steam_crypt_rsa_ints(key, &mmpi, &empi))
        return NULL;

    gcry_mpi_scan(&dmpi, GCRYMPI_FMT_STD, bytes->data, bytes->len, NULL);
    kize = gcry_mpi_get_nbits(mmpi) / 8;

    gcry_sexp_build(&kata, NULL, "(public-key(rsa(n %m)(e %m)))", mmpi, empi);
    gcry_sexp_build(&data, NULL, "(data(flags oaep)(value %m))",  dmpi);

    gcry_mpi_release(dmpi);
    gcry_mpi_release(empi);
    gcry_mpi_release(mmpi);

    res = gcry_pk_encrypt(&cata, data, kata);
    gcry_sexp_release(data);
    gcry_sexp_release(kata);

    if (res != 0) {
        gcry_sexp_release(cata);
        return NULL;
    }

    data = gcry_sexp_find_token(cata, "a", 0);
    dmpi = gcry_sexp_nth_mpi(data, 1, GCRYMPI_FMT_STD);
    gcry_sexp_release(data);
    gcry_sexp_release(cata);

    ret  = g_byte_array_new();
    g_byte_array_set_size(ret, kize);

    gcry_mpi_print(GCRYMPI_FMT_STD, ret->data, ret->len, &size, dmpi);
    gcry_mpi_release(dmpi);

    g_warn_if_fail(size <= kize);
    g_byte_array_set_size(ret, size);

    return ret;
}

 /**
 * Encrypts a #GByteArray via an RSA public key. This uses the static
 * key associated with the #SteamIdUniv. The returned #GByteArray should
 * be freed with #g_byte_array_free() when no longer needed.
 *
 * @param univ  The #SteamIdUniv.
 * @param bytes The #GByteArray.
 *
 * @return The encrypted #GByteArray or NULL on error.
 **/
GByteArray *steam_crypt_rsa_enc_univ(SteamIdUniv univ, const GByteArray *bytes)
{
    GByteArray *key;
    GByteArray *ret;

    static const guint8 public[] = {
        0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81,
        0x87, 0x02, 0x81, 0x81, 0x00, 0xDF, 0xEC, 0x1A, 0xD6, 0x2C, 0x10, 0x66,
        0x2C, 0x17, 0x35, 0x3A, 0x14, 0xB0, 0x7C, 0x59, 0x11, 0x7F, 0x9D, 0xD3,
        0xD8, 0x2B, 0x7A, 0xE3, 0xE0, 0x15, 0xCD, 0x19, 0x1E, 0x46, 0xE8, 0x7B,
        0x87, 0x74, 0xA2, 0x18, 0x46, 0x31, 0xA9, 0x03, 0x14, 0x79, 0x82, 0x8E,
        0xE9, 0x45, 0xA2, 0x49, 0x12, 0xA9, 0x23, 0x68, 0x73, 0x89, 0xCF, 0x69,
        0xA1, 0xB1, 0x61, 0x46, 0xBD, 0xC1, 0xBE, 0xBF, 0xD6, 0x01, 0x1B, 0xD8,
        0x81, 0xD4, 0xDC, 0x90, 0xFB, 0xFE, 0x4F, 0x52, 0x73, 0x66, 0xCB, 0x95,
        0x70, 0xD7, 0xC5, 0x8E, 0xBA, 0x1C, 0x7A, 0x33, 0x75, 0xA1, 0x62, 0x34,
        0x46, 0xBB, 0x60, 0xB7, 0x80, 0x68, 0xFA, 0x13, 0xA7, 0x7A, 0x8A, 0x37,
        0x4B, 0x9E, 0xC6, 0xF4, 0x5D, 0x5F, 0x3A, 0x99, 0xF9, 0x9E, 0xC4, 0x3A,
        0xE9, 0x63, 0xA2, 0xBB, 0x88, 0x19, 0x28, 0xE0, 0xE7, 0x14, 0xC0, 0x42,
        0x89, 0x02, 0x01, 0x11
    };

    static const guint8 beta[] = {
        0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81,
        0x87, 0x02, 0x81, 0x81, 0x00, 0xAE, 0xD1, 0x4B, 0xC0, 0xA3, 0x36, 0x8B,
        0xA0, 0x39, 0x0B, 0x43, 0xDC, 0xED, 0x6A, 0xC8, 0xF2, 0xA3, 0xE4, 0x7E,
        0x09, 0x8C, 0x55, 0x2E, 0xE7, 0xE9, 0x3C, 0xBB, 0xE5, 0x5E, 0x0F, 0x18,
        0x74, 0x54, 0x8F, 0xF3, 0xBD, 0x56, 0x69, 0x5B, 0x13, 0x09, 0xAF, 0xC8,
        0xBE, 0xB3, 0xA1, 0x48, 0x69, 0xE9, 0x83, 0x49, 0x65, 0x8D, 0xD2, 0x93,
        0x21, 0x2F, 0xB9, 0x1E, 0xFA, 0x74, 0x3B, 0x55, 0x22, 0x79, 0xBF, 0x85,
        0x18, 0xCB, 0x6D, 0x52, 0x44, 0x4E, 0x05, 0x92, 0x89, 0x6A, 0xA8, 0x99,
        0xED, 0x44, 0xAE, 0xE2, 0x66, 0x46, 0x42, 0x0C, 0xFB, 0x6E, 0x4C, 0x30,
        0xC6, 0x6C, 0x5C, 0x16, 0xFF, 0xBA, 0x9C, 0xB9, 0x78, 0x3F, 0x17, 0x4B,
        0xCB, 0xC9, 0x01, 0x5D, 0x3E, 0x37, 0x70, 0xEC, 0x67, 0x5A, 0x33, 0x48,
        0xF7, 0x46, 0xCE, 0x58, 0xAA, 0xEC, 0xD9, 0xFF, 0x4A, 0x78, 0x6C, 0x83,
        0x4B, 0x02, 0x01, 0x11
    };

    static const guint8 internal[] = {
        0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81,
        0x87, 0x02, 0x81, 0x81, 0x00, 0xA8, 0xFE, 0x01, 0x3B, 0xB6, 0xD7, 0x21,
        0x4B, 0x53, 0x23, 0x6F, 0xA1, 0xAB, 0x4E, 0xF1, 0x07, 0x30, 0xA7, 0xC6,
        0x7E, 0x6A, 0x2C, 0xC2, 0x5D, 0x3A, 0xB8, 0x40, 0xCA, 0x59, 0x4D, 0x16,
        0x2D, 0x74, 0xEB, 0x0E, 0x72, 0x46, 0x29, 0xF9, 0xDE, 0x9B, 0xCE, 0x4B,
        0x8C, 0xD0, 0xCA, 0xF4, 0x08, 0x94, 0x46, 0xA5, 0x11, 0xAF, 0x3A, 0xCB,
        0xB8, 0x4E, 0xDE, 0xC6, 0xD8, 0x85, 0x0A, 0x7D, 0xAA, 0x96, 0x0A, 0xEA,
        0x7B, 0x51, 0xD6, 0x22, 0x62, 0x5C, 0x1E, 0x58, 0xD7, 0x46, 0x1E, 0x09,
        0xAE, 0x43, 0xA7, 0xC4, 0x34, 0x69, 0xA2, 0xA5, 0xE8, 0x44, 0x76, 0x18,
        0xE2, 0x3D, 0xB7, 0xC5, 0xA8, 0x96, 0xFD, 0xE5, 0xB4, 0x4B, 0xF8, 0x40,
        0x12, 0xA6, 0x17, 0x4E, 0xC4, 0xC1, 0x60, 0x0E, 0xB0, 0xC2, 0xB8, 0x40,
        0x4D, 0x9E, 0x76, 0x4C, 0x44, 0xF4, 0xFC, 0x6F, 0x14, 0x89, 0x73, 0xB4,
        0x13, 0x02, 0x01, 0x11
    };

    g_return_val_if_fail(bytes != NULL, NULL);

    key = g_byte_array_new();

    switch (univ) {
    case STEAM_ID_UNIV_PUBLIC:
        g_byte_array_append(key, public, STEAM_UTIL_ARR_SIZE(public));
        break;

    case STEAM_ID_UNIV_BETA:
        g_byte_array_append(key, beta, STEAM_UTIL_ARR_SIZE(beta));
        break;

    case STEAM_ID_UNIV_INTERNAL:
        g_byte_array_append(key, internal, STEAM_UTIL_ARR_SIZE(internal));
        break;

    default:
        g_byte_array_free(key, TRUE);
        return NULL;
    }

    ret = steam_crypt_rsa_enc(key, bytes);
    g_byte_array_free(key, TRUE);

    return ret;
}

/**
 * Decrypts a #GByteArray via an encryption key. This decrypts with the
 * key via AES-CBC-PKCS7. The returned #GByteArray should be freed with
 * #g_byte_array_free() when no longer needed.
 *
 * @param key   The key.
 * @param bytes The #GByteArray.
 *
 * @return The decrypted #GByteArray or NULL on error.
 **/
GByteArray *steam_crypt_sym_dec(const GByteArray *key, const GByteArray *bytes)
{
    GByteArray       *ret;
    GByteArray       *iv;
    gcry_cipher_hd_t  ciph;
    gcry_error_t      res;
    guint8            pad;

    static gsize bize = 0;

    g_return_val_if_fail(key   != NULL, NULL);
    g_return_val_if_fail(bytes != NULL, NULL);

    if (G_UNLIKELY(bytes->len < 17))
        return NULL;

    if (G_UNLIKELY(bize == 0))
        bize = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);

    gcry_cipher_open(&ciph, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(ciph, key->data, key->len);

    iv = g_byte_array_new();
    g_byte_array_set_size(iv, 16);

    res = gcry_cipher_decrypt(ciph, iv->data, iv->len, bytes->data, iv->len);
    gcry_cipher_close(ciph);

    if (res != 0) {
        g_byte_array_free(iv, TRUE);
        return NULL;
    }

    gcry_cipher_open(&ciph, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setiv(ciph, iv->data, iv->len);
    gcry_cipher_setkey(ciph, key->data, key->len);

    ret = g_byte_array_new();
    g_byte_array_set_size(ret, bytes->len - iv->len);

    res = gcry_cipher_decrypt(ciph, ret->data, ret->len,
                              bytes->data + iv->len, ret->len);
    gcry_cipher_close(ciph);
    g_byte_array_free(iv, TRUE);

    pad = (ret->len > 0) ? ret->data[ret->len - 1] : 0;
    g_warn_if_fail(pad <= bize);

    if ((res != 0) || (pad > bize) || (pad > ret->len)) {
        g_byte_array_free(ret, TRUE);
        return NULL;
    }

    g_byte_array_set_size(ret, ret->len - pad);
    return ret;
}

/**
 * Encrypts a #GByteArray via an encryption key. This encrypts with the
 * key via AES-CBC-PKCS7. The returned #GByteArray should be freed with
 * #g_byte_array_free() when no longer needed.
 *
 * @param key   The key.
 * @param bytes The #GByteArray.
 *
 * @return The encrypted #GByteArray or NULL on error.
 **/
GByteArray *steam_crypt_sym_enc(const GByteArray *key, const GByteArray *bytes)
{
    GByteArray       *ret;
    GByteArray       *iv;
    GByteArray       *pytes;
    gcry_cipher_hd_t  ciph;
    gcry_error_t      res;
    guint8            pad;

    static gsize bize = 0;

    g_return_val_if_fail(key   != NULL, NULL);
    g_return_val_if_fail(bytes != NULL, NULL);

    if (G_UNLIKELY(bize == 0))
        bize = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);

    iv = g_byte_array_new();
    g_byte_array_set_size(iv, 16);
    random_bytes(iv->data, iv->len);

    gcry_cipher_open(&ciph, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(ciph, key->data, key->len);

    ret = g_byte_array_new();
    g_byte_array_set_size(ret, iv->len);

    res = gcry_cipher_encrypt(ciph, ret->data, ret->len, iv->data, iv->len);
    gcry_cipher_close(ciph);

    if (res != 0) {
        g_byte_array_free(ret, TRUE);
        g_byte_array_free(iv,  TRUE);
        return NULL;
    }

    gcry_cipher_open(&ciph, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setiv(ciph, iv->data, iv->len);
    gcry_cipher_setkey(ciph, key->data, key->len);

    pad   = bize - (bytes->len % bize);
    pytes = g_byte_array_new();

    g_byte_array_append(pytes, bytes->data, bytes->len);
    g_byte_array_set_size(pytes, pytes->len + pad);
    memset(pytes->data + bytes->len, pad, pad);
    g_byte_array_set_size(ret, ret->len + pytes->len);

    res = gcry_cipher_encrypt(ciph, ret->data + iv->len, pytes->len,
                              pytes->data, pytes->len);
    gcry_cipher_close(ciph);
    g_byte_array_free(pytes, TRUE);
    g_byte_array_free(iv,    TRUE);

    if (res != 0) {
        g_byte_array_free(ret, TRUE);
        return NULL;
    }

    return ret;
}
