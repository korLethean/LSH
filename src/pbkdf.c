/*
 * pbkdf.c
 *
 *  Created on: 2018. 6. 22.
 *      Author: HD
 */


#include <string.h>
#include "../include/pbkdf.h"

lsh_err lsh_pbkdf(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, lsh_uint iteration_count, lsh_uint key_len, lsh_uint hash_len, lsh_u8 *output)
{
	lsh_err result;

	double len;

	len = ceil((double) key_len / (double) hash_len);

	for(int i = 0 ; i < (int) len ; i++)
	{
		for(int j = 0 ; j < iteration_count ; j++)
		{
			// HMAC called
			// exclusive-or
		}
	}

	return result;
}

lsh_err lsh_pbkdf_digest()
{
	lsh_err result;

	return result;
}
