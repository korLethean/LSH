#include <string.h>
#include <math.h>
#include "../include/drbg.h"

void operation_add(unsigned char *arr, int num)
{
	int arr_size = strlen(arr);
	int temp;
	int carry = 0;

    temp = arr[arr_size - 1];
    arr[arr_size - 1] += num;

    if(arr[arr_size - 1] < temp)
    {
        carry += 1;
        for(int i = arr_size - 2 ; i > -1 ; i--)
        {
            temp = arr[i];
            arr[i] += carry;
            carry = 0;
            if(arr[i] < temp)
                carry += 1;
            else
                break;
        }
    }
}

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
		hash_data[0] = 49 + i;	//0x00 + i

		if(!i) {
			for(int j = 0 ; j < strlen(N) ; j++)
				hash_data[1 + j] = N[j];

			for(r = 0; r < strlen(data) ; r++)
				hash_data[w++] = data[r];

			hash_data[w] = '\0';
		}
		for(int t = 0 ; t < strlen(hash_data) ; t++)
		{
			printf("%02x", hash_data[t]);
		}
		printf("     *** %d ***\n", i);

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

	lsh_uint *hash_data;
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 0, counter = 1;
	int flag = 0;
	int output_index = 55;

	if (ctx == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(algtype))
		Block_Bit = LSH256_HASH_VAL_MAX_BYTE_LEN * 8;
	else if(LSH_IS_LSH512(algtype))
		Block_Bit = LSH512_HASH_VAL_MAX_BYTE_LEN * 8;
	n = 2;

	for(int i = 0 ; i < n ; i++)
	{
		operation_add(ctx->working_state_V, i);
		r = LSH_GET_HASHBIT(algtype) - 1;
		w = r;

		while(counter < LSH_GET_HASHBIT(algtype))
		{
			hash_data[w--] = ctx->working_state_V[r--];
			counter++;
		}

		result = lsh_digest(algtype, hash_data, strlen(hash_data) * 8, hash_result[i]);
	}

	w = 0;
	for(r = 0 ; r < output_index ; r++)
	{
		if(r == LSH_GET_HASHBYTE(algtype))
		{
			flag += 1;
			output_index -= LSH_GET_HASHBYTE(algtype);
			r = 0;
		}

		ctx->working_state_C[w++] = hash_result[flag][r];
	}
}


lsh_err drbg_lsh_init(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, const lsh_u8 *nonce, const lsh_u8 *per_string)
{
	lsh_err result;

	lsh_u8 input[1024];

	int r, w, arr_size;

	arr_size = strlen(entropy);
	for(r = 0, w = 0 ; r < arr_size ; r++)
		input[w++] = entropy[r];

	arr_size = strlen(nonce);
	for(r = 0 ; r < arr_size ; r++)
		input[w++] = nonce[r];

	arr_size = strlen(per_string);
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


lsh_err drbg_lsh_output_gen(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *add_input)
{
	lsh_err result;

	lsh_u8 hash_data[1024] = {'\0', };
	lsh_u8 hash_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w, arr_size;

	hash_data[0] = 0x02;
	arr_size = strlen(ctx->working_state_V);
	for(r = 0 , w = 1 ; r < arr_size ; r++)
		hash_data[w++] = ctx->working_state_V[r];

	arr_size = strlen(add_input);
	for(r = 0 ; r < arr_size ; r++)
		hash_data[w++] = add_input[r];
	hash_data[w] = '\0';

	result = lsh_digest(algtype, hash_data, strlen(hash_data) * 8, hash_result);
	if (result != LSH_SUCCESS)
		return result;

	arr_size = strlen(hash_result);
	for(int i = 0 ; i < hash_result ; i++)
		ctx->working_state_V[i] = hash_result[i];

	hash_data[0] = 0x03;
	arr_size = strlen(ctx->working_state_V);
	for(r = 0, w = 1 ; r < arr_size ; r++)
		hash_data[w++] = ctx->working_state_V[r];
	hash_data[w] = '\0';

	result = lsh_digest(algtype, hash_data, strlen(hash_data) * 8, hash_result);
	if (result != LSH_SUCCESS)
		return result;

	// **** **** //


	return result;
}


lsh_err drbg_lsh_digest(lsh_type algtype, lsh_u8 *entropy, lsh_u8 *nonce, lsh_u8 *per_string, lsh_u8 *add_input)
{
	struct DRBG_LSH_Context ctx;
	int result;

	result = drbg_lsh_init(&ctx, algtype, entropy, nonce, per_string);
	if (result != LSH_SUCCESS)
		return result;

	/*result = drbg_lsh_reseed(&ctx, algtype, entropy, add_input);
	if (result != LSH_SUCCESS)
		return result;*/

	return result;
}
