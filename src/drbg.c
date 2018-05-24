#include <string.h>
#include <math.h>
#include "../include/drbg.h"

lsh_err drbg_derivation_func(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *data, lsh_u8 *output)
{
	lsh_err result;

	lsh_uint Block_Bit;
	lsh_uint Seed_Bit;
	lsh_u8 N[8];
	lsh_uint len_seed;

	lsh_u8 hash_data[1024] = {'\0', };
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 9;
	int flag = 0;
	int output_index = 55;

	if (ctx == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(algtype))
	{
		Block_Bit = LSH256_HASH_VAL_MAX_BYTE_LEN * 8;
		Seed_Bit = 440;
		strcpy(N, "000001B8");
	}
	else if(LSH_IS_LSH512(algtype))
	{
		Block_Bit = LSH512_HASH_VAL_MAX_BYTE_LEN * 8;
		Seed_Bit = 888;
		strcpy(N, "00000378");
	}
	len_seed = 2;

	for(int i = 0 ; i < len_seed ; i++)
	{
		hash_data[0] = 49 + i;

		if(!i) {
			for(int j = 0 ; j < strlen(N) ; j++)
				hash_data[1 + j] = N[j];

			for(r = 0; r < strlen(data) ; r += 2)
			{
				lsh_u8 temp_arr[3] = {data[r], data[r+1], '\0'};
				hash_data[w++] = strtol(temp_arr, NULL, 16);
			}
			hash_data[w] = '\0';
		}

		result = lsh_digest(algtype, hash_data, strlen(hash_data) * 8, hash_result[i]);
	}

	w = 0;
	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == LSH_GET_HASHBYTE(algtype))
		{
			flag += 1;
			output_index -= LSH_GET_HASHBYTE(algtype);
			i = 0;
		}

		output[w++] = hash_result[flag][i];
	}

	return result;
}


lsh_err drbg_lsh_inner_output_gen(struct DRBG_LSH_Context *ctx, lsh_type algtype)
{
	lsh_err result;

	lsh_uint Block_Bit;
	lsh_uint n;

	lsh_uint *temp;
	lsh_uint hash_data;
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 0;
	int flag = 0;
	int output_index = 55;

	if (ctx == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(algtype))
		Block_Bit = LSH256_HASH_VAL_MAX_BYTE_LEN * 8;
	else if(LSH_IS_LSH512(algtype))
		Block_Bit = LSH512_HASH_VAL_MAX_BYTE_LEN * 8;
	n = 2;

	temp = ctx->working_state_V;

	for(int i = 0 ; i < n ; i++)
	{
		//********** need V + 1 mod 2^blockbits **********//

		result = lsh_digest(algtype, temp, strlen(temp) * 8, hash_result[i]);
	}

	w = 0;
	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == LSH_GET_HASHBYTE(algtype))
		{
			flag += 1;
			output_index -= LSH_GET_HASHBYTE(algtype);
			i = 0;
		}

		ctx->working_state_C[w++] = hash_result[flag][i];
	}
}


lsh_err drbg_lsh_init(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, const lsh_u8 *nonce, const lsh_u8 *per_string)
{
	lsh_err result;

	lsh_u8 input[1024];

	int r, w, arr_size;

	arr_size = sizeof(entropy) / sizeof(lsh_u8);
	for(r = 0, w = 0 ; r < arr_size ; r++)
		input[w++] = entropy[r];

	arr_size = sizeof(nonce) / sizeof(lsh_u8);
	for(r = 0 ; r < arr_size ; r++)
		input[w++] = nonce[r];

	arr_size = sizeof(per_string) / sizeof(lsh_u8);
	for(r = 0 ; r < arr_size ; r++)
		input[w++] = per_string[r];
	input[w] = '\0';

	result = drbg_derivation_func(ctx, algtype, input, ctx->working_state_V);
	if (result != LSH_SUCCESS)
		return result;

	input[0] = 0x00;
	arr_size = sizeof(ctx->working_state_V) / sizeof(lsh_u8);
	for(r = 0, w = 1 ; r < arr_size ; r++)
		input[w++] = ctx->working_state_V[r];
	input[w] = '\0';

	result = drbg_derivation_func(ctx, algtype, input, ctx->working_state_C);

	return result;
}


lsh_err drbg_lsh_reseed(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, const lsh_u8 *add_input)
{
	lsh_err result;

	lsh_u8 input[1024];

	int r, w, arr_size;

	input[0] = 0x01;

	arr_size = sizeof(ctx->working_state_V) / sizeof(lsh_u8);
	for(r = 0, w = 1 ; r < arr_size ; r++)
		input[w++] = ctx->working_state_V[r];

	arr_size = sizeof(entropy) / sizeof(lsh_u8);
	for(r = 0 ; r < arr_size ; r++)
		input[w++] = entropy[r];

	arr_size = sizeof(add_input) / sizeof(lsh_u8);
	for(r = 0 ; r < arr_size ; r++)
		input[w++] = add_input[r];
	input[w] = '\0';

	result = drbg_derivation_func(ctx, algtype, input, ctx->working_state_V);
	if (result != LSH_SUCCESS)
		return result;

	input[0] = 0x00;
	arr_size = sizeof(ctx->working_state_V) / sizeof(lsh_u8);
	for(r = 0, w = 1 ; r < arr_size ; r++)
		input[w++] = ctx->working_state_V[r];
	input[w] = '\0';

	result = drbg_derivation_func(ctx, algtype, input, ctx->working_state_C);

	return result;
}



lsh_err drbg_lsh_digest(lsh_type algtype, lsh_u8 *data)
{
	struct DRBG_LSH_Context ctx;
	int result;


	result = drbg_lsh_inner_output_gen(&ctx, algtype);
	if (result != LSH_SUCCESS)
		return result;

	return result;
}
