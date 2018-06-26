/*
 * pbkdf.c
 *
 *  Created on: 2018. 6. 22.
 *      Author: HD
 */

#include "../include/pbkdf.h"

#define KEY_MAX_SIZE 128

lsh_err lsh_pbkdf_gen(lsh_type algtype, int hash_len, lsh_u8 *U, lsh_uint size_u, lsh_u8 *T, int t_index, int t_num, lsh_u8 *password, lsh_uint pass_size, lsh_uint iteration_count, FILE *fp)
{
	lsh_err result;
	int index = t_index;

	for(int i = 0 ; i < iteration_count ; i++)
	{
		if(!i)
			result = hmac_lsh_digest(algtype, password, pass_size, U, size_u, U);
		else
			result = hmac_lsh_digest(algtype, password, pass_size, U, hash_len, U);
		if(result != LSH_SUCCESS)
			return result;

		for(int j = 0 ; j < hash_len ; j++)
			T[index++] ^=  U[j];
		index = t_index;

		fprintf(fp, "U%d = ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			fprintf(fp, "%02x", U[j]);
		fprintf(fp, "\nT%d = ", t_num);
		for(int j = 0 ; j < hash_len ; j++)
			fprintf(fp, "%02x", T[index++]);
		fprintf(fp, "\n\n");

		index = t_index;
	}
	fprintf(fp, "\n");

	return result;
}

lsh_err lsh_pbkdf_digest(lsh_type algtype, lsh_u8 *password, lsh_u8 *salt, int pass_size, int salt_size, lsh_uint iteration_count, lsh_uint loop_count, lsh_uint key_len, lsh_uint hash_len, FILE *fp)
{
	lsh_err result;

	lsh_u8 U[KEY_MAX_SIZE] = {'\0', };
	lsh_u8 *T;

	double len;
	int r, w;
	int size_u, size_t;

	//len = ceil((double) key_len / (double) hash_len);
	size_t = loop_count * (key_len / 8) / 2;

	T = (lsh_u8*) malloc(sizeof(lsh_u8) * size_t);

	for(int i = 0 ; i < size_t ; i++)
		T[i] = '\0';

	for(int i = 0 ; i < loop_count ; i++)
	{
		int t_index = size_t / loop_count * i;
		printf("%d \n", t_index);

		for(r = 0, w = 0 ; r < salt_size ; r++)
			U[w++] = salt[r];
		U[w++] = 0;
		U[w++] = 0;
		U[w++] = 0;
		U[w] = i + 1;
		size_u = salt_size + 4;
		/********** outer loop OUTPUT **********/
		fprintf(fp, "U0 = ");
		for(int j = 0 ; j < size_u ; j++)
			fprintf(fp, "%02x", U[j]);
		fprintf(fp, "\n");

		result = lsh_pbkdf_gen(algtype, hash_len, U, size_u, T, t_index, i + 1, password, pass_size, iteration_count, fp);
		if(result != LSH_SUCCESS) {
			printf("df \n");
			return result;
		}
	}

	fprintf(fp, "MK = ");
	for(int i = 0 ; i < size_t ; i++)
		fprintf(fp, "%02x", T[i]);
	fprintf(fp, "\n");

	free(T);
	return result;
}
