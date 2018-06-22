/*
 * pbkdf.h
 *
 *  Created on: 2018. 6. 22.
 *      Author: HD
 */

#ifndef INCLUDE_PBKDF_H_
#define INCLUDE_PBKDF_H_

#include <stdbool.h>
#include "hmac.h"

lsh_err lsh_pbkdf(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, lsh_uint iteration_count, lsh_uint key_len, lsh_uint hash_len, lsh_u8 *output);

lsh_err lsh_pbkdf_digest();

#endif /* INCLUDE_PBKDF_H_ */
