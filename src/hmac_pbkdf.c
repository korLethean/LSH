/*
 * hmac_pbkdf.c
 *
 *  Created on: 2018. 6. 26.
 *      Author: HD
 */

#include <stdio.h>
#include "../include/hmac_pbkdf.h"

lsh_err hmac_kdf_ctr_digest(lsh_type algtype, int loop_count, int byte_r, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int ct_len, lsh_uint len, lsh_u8 output, FILE *fp)
{
	lsh_err result;
	lsh_u8 *input;

	input = (lsh_u8*) malloc(sizeof(lsh_u8) * (byte_r + Ki_len, label_len, ct_len + 3));	// 3 = 0x00(1) || [L]2(2)

	for(int i = 0 ; i < loop_count ; i++)
	{


		if(result != LSH_SUCCESS)
			return result;
	}

	free(input);

	return result;
}

lsh_err hmac_kdf_fb_digest(lsh_type algtype, int loop_count, lsh_u8 output, FILE *fp)
{
	lsh_err result;

	return result;
}

lsh_err hmac_kdf_dp_digest(lsh_type algtype, int loop_count, lsh_u8 output, FILE *fp)
{
	lsh_err result;

	return result;
}

lsh_err hmac_kdf_digest(int mode, lsh_type algtype, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int context_len, lsh_uint r, lsh_uint len, lsh_uint hash_len, FILE *fp)
{
	lsh_err result;
	lsh_u8 *Ko;
	double n;

	int byte_r = r / 8;

	n = ceil((double)len / (double) hash_len);

	Ko = (lsh_u8*) malloc(sizeof(lsh_u8) * len);

	if(mode == CTR_MODE)
	{
		result = hmac_kdf_ctr_digest(algtype, (int) n, byte_r, Ki, Ki_len, label, label_len, context, context_len, len, Ko, fp);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(mode == FB_MODE)
	{
		result = hmac_kdf_fb_digest(algtype, (int) n, Ko, fp);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(mode == DP_MODE)
	{
		result = hmac_kdf_dp_digest(algtype, (int) n, Ko, fp);
		if(result != LSH_SUCCESS)
			return result;
	}
	else
		printf("unknown mode \n");

	free(Ko);

	return result;
}
