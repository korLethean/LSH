/*
 * pbkdf.c
 *
 *  Created on: 2018. 6. 22.
 *      Author: HD
 */

#include "../include/pbkdf.h"

#define KEY_MAX_SIZE 128

lsh_err lsh_pbkdf_gen(lsh_type algtype, lsh_u8 *U, lsh_u8 *password, lsh_uint iteration_count, int len, lsh_u8 *output, FILE *fp)
{
	lsh_err result;


	for(int i = 0 ; i < iteration_count ; i++)
	{
		// HMAC called
		// exclusive-or
	}

	return result;
}

lsh_err lsh_pbkdf_digest(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, int pass_size, int salt_size, lsh_uint iteration_count, lsh_uint key_len, lsh_uint hash_len, lsh_u8 *output, FILE *fp)
{
	lsh_err result;

	lsh_u8 U[KEY_MAX_SIZE] = {'\0', };
	lsh_u8 *T;

	double len;
	int r, w;


	len = ceil((double) key_len / (double) hash_len);

	T = (lsh_u8*) malloc(sizeof(lsh_u8) * ((int)len + 1) * (key_len / 8));

	for(int i = 0 ; i < (int) len ; i++)
	{
		for(r = 0, w = 0 ; r < salt_size ; r++)
			U[w++] = salt[r];
		U[w] = i;

		result = lsh_pbkdf_gen(algtype, U, password, iteration_count, len, output, fp);
		if(result != LSH_SUCCESS)
			return result;
	}

	free(T);
	return result;
}
