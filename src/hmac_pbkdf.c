/*
 * hmac_pbkdf.c
 *
 *  Created on: 2018. 6. 26.
 *      Author: HD
 */

#include "../include/hmac_pbkdf.h"

lsh_err hmac_pbkdf_ctr_digest(lsh_type algtype, int loop_count, lsh_u8 output)
{
	lsh_err result;
	lsh_u8 *input;

	return result;
}

lsh_err hmac_kdf_fb_digest(lsh_type algtype, int loop_count, lsh_u8 output)
{
	lsh_err result;

	return result;
}

lsh_err hmac_kdf_dp_digest(lsh_type algtype, int loop_count, lsh_u8 output)
{
	lsh_err result;

	return result;
}

lsh_err hmac_kdf_digest(int mode, lsh_type algtype, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int context_len, lsh_uint r, lsh_uint len, lsh_uint hash_len)
{
	lsh_err result;
	lsh_u8 *digest;
	double n;
	int bit_unit;

	n = ceil((double)len / (double) hash_len);

	//malloc

	if(mode == CTR_MODE)
	{
		result = hmac_pbkdf_ctr_digest(algtype, n);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(mode == FB_MODE)
	{
		result = hmac_pbkdf_fb_digest(algtype, n);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(mode == DP_MODE)
	{
		result = hmac_pbkdf_dp_digest(algtype, n);
		if(result != LSH_SUCCESS)
			return result;
	}
	else
		printf("unknown mode \n");

	return result;
}
