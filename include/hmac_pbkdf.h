/*
 * hmac_pbkdf.h
 *
 *  Created on: 2018. 6. 26.
 *      Author: HD
 */

#ifndef INCLUDE_HMAC_PBKDF_H_
#define INCLUDE_HMAC_PBKDF_H_

#include "hmac.h"

#define CTR_MODE 1
#define FB_MODE 2
#define DP_MODE 3

lsh_err hmac_kdf_ctr_digest(lsh_type algtype, int loop_count, int byte_r, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int ct_len, lsh_uint len, lsh_u8 *output, FILE *fp);

lsh_err hmac_kdf_fb_digest(lsh_type algtype, int loop_count, lsh_u8 *output, FILE *fp);

lsh_err hmac_kdf_dp_digest(lsh_type algtype, int loop_count, lsh_u8 *output, FILE *fp);

lsh_err hmac_kdf_digest(int mode, lsh_type algtype, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int context_len, lsh_uint r, lsh_uint len, lsh_uint hash_len, FILE *fp);

#endif /* INCLUDE_HMAC_PBKDF_H_ */
