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

#ifndef _STEAM_CRYPT_H
#define _STEAM_CRYPT_H

#include <glib.h>

#include "steam-id.h"


guint32 steam_crypt_crc32(const GByteArray *bytes);

GByteArray *steam_crypt_rsa_enc(const GByteArray *key, const GByteArray *bytes);

GByteArray *steam_crypt_rsa_enc_univ(SteamIdUniv univ, const GByteArray *bytes);

GByteArray *steam_crypt_sym_dec(const GByteArray *key, const GByteArray *bytes);

GByteArray *steam_crypt_sym_enc(const GByteArray *key, const GByteArray *bytes);

#endif /* _STEAM_CRYPT_H */
