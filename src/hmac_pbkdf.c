/*
 * hmac_pbkdf.c
 *
 *  Created on: 2018. 6. 26.
 *      Author: HD
 */

#include "../include/hmac_pbkdf.h"

lsh_err hmac_pbkdf_ctr_digest()
{
	lsh_err result;

	return result;
}

lsh_err hmac_kdf_fb_digest()
{
	lsh_err result;

	return result;
}

lsh_err hmac_kdf_dp_digest()
{
	lsh_err result;

	return result;
}

lsh_err hmac_pbkdf_digest(int mode)
{
	lsh_err result;

	if(mode == CTR_MODE)
		hmac_pbkdf_ctr_digest();
	else if(mode == FB_MODE)
		hmac_pbkdf_fb_digest();
	else if(mode == DP_MODE)
		hmac_pbkdf_dp_digest();
	else
		printf("unknown mode \n");

	return result;
}
