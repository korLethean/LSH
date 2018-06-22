/*
 * pbkdf.h
 *
 *  Created on: 2018. 6. 22.
 *      Author: HD
 */

#ifndef INCLUDE_PBKDF_H_
#define INCLUDE_PBKDF_H_

#include <stdio.h>
#include <stdbool.h>
#include "hmac.h"

lsh_err lsh_pbkdf_gen(lsh_type algtype, lsh_u8 *U, lsh_u8 *password, lsh_uint iteration_count, int len, lsh_u8 *output, FILE *fp);

lsh_err lsh_pbkdf_digest(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, int pass_size, int salt_size, lsh_uint iteration_count, lsh_uint key_len, lsh_uint hash_len, lsh_u8 *output, FILE *fp);

#endif /* INCLUDE_PBKDF_H_ */
