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

lsh_err lsh_pbkdf_gen(lsh_type algtype, int hash_len, lsh_u8 *U, lsh_uint size_u, lsh_u8 *T, int t_index, int t_num, lsh_u8 *password, lsh_uint pass_size, lsh_uint iteration_count, FILE *fp, bool tv);

lsh_err lsh_pbkdf_digest(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, int pass_size, int salt_size, lsh_uint iteration_count, lsh_uint loop_count, lsh_uint key_len, lsh_uint hash_len, FILE *fp, bool tv);

#endif /* INCLUDE_PBKDF_H_ */
