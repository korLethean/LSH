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

lsh_err hmac_kdf_ctr_digest();

lsh_err hmac_kdf_fb_digest();

lsh_err hmac_kdf_dp_digest();

lsh_err hmac_kdf_digest(int mode);


#endif /* INCLUDE_HMAC_PBKDF_H_ */
