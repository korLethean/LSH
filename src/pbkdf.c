/*
 * pbkdf.c
 *
 *  Created on: 2018. 6. 22.
 *      Author: HD
 */

#include "../include/pbkdf.h"

#define KEY_MAX_SIZE 128

lsh_err lsh_pbkdf_gen(lsh_type algtype, lsh_u8 *U, lsh_uint size_u, lsh_u8 *T, int t_index, lsh_u8 *password, lsh_uint pass_size, lsh_uint iteration_count, lsh_u8 *output, FILE *fp)
{
	lsh_err result;
	int hash_len = LSH_GET_HASHBYTE(algtype);

	for(int i = 0 ; i < iteration_count ; i++)
	{
		if(!i)
			hmac_lsh_digest(algtype, password, pass_size, U, size_u, U);
		else
			hmac_lsh_digest(algtype, password, pass_size, U, hash_len, U);
		for(int j = 0 ; j < hash_len ; j++)
			T[j] = T[j] ^ U[j];

		printf("(%d) inner loop \n", i + 1);
		printf("U%d = ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", U[j]);
		printf("\nT%d = ", t_index);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", T[j]);
		printf("\n");
	}

	return result;
}

lsh_err lsh_pbkdf_digest(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, int pass_size, int salt_size, lsh_uint iteration_count, lsh_uint loop_count, lsh_uint key_len, lsh_uint hash_len, lsh_u8 *output, FILE *fp)
{
	lsh_err result;

	lsh_u8 U[KEY_MAX_SIZE] = {'\0', };
	lsh_u8 *T;

	double len;
	int r, w;
	int size_u, size_t;

	//len = ceil((double) key_len / (double) hash_len);
	len = loop_count;
	size_u = 0;
	size_t = loop_count * (key_len / 8);

	T = (lsh_u8*) malloc(sizeof(lsh_u8) * size_t);

	for(int i = 0 ; i < (int) len ; i++)
	{
		for(int j = 0 ; j < size_t ; j++)
			T[i] = '\0';

		for(r = 0, w = 0 ; r < salt_size ; r++)
			U[w++] = salt[r];
		U[w] = i + 1;
		size_u = salt_size + 1;
		/********** outer loop OUTPUT **********/
		printf("U0 = ");
		for(int j = 0 ; j < size_u ; j++)
			printf("%02x", U[j]);
		printf("\n");

		result = lsh_pbkdf_gen(algtype, U, size_u, T, i + 1, password, pass_size, iteration_count, output, fp);
		if(result != LSH_SUCCESS)
			return result;
	}

	free(T);
	return result;
}
