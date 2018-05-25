#include <string.h>
#include "../include/drbg.h"

void operation_add(unsigned char *arr, int ary_size, int start_index, unsigned int num)
{
	unsigned int current;
	unsigned int carry = 0;
	start_index++;

	current = arr[ary_size - start_index];
	current += num;
	carry = (current >> 8);
	arr[ary_size - start_index] = (unsigned char) current;

    while(carry)
    {
    	start_index++;
    	current = arr[ary_size - start_index];
		current += carry;
		carry = (current >> 8);
		arr[ary_size - start_index] = (unsigned char) current;
    }
}

lsh_err drbg_derivation_func(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *data, int data_size, lsh_u8 *output)
{
	lsh_err result;

	lsh_uint Block_Bit;
	lsh_uint Seed_Bit;
	lsh_u8 N[8];
	lsh_uint len_seed;

	lsh_u8 hash_data[1024] = {'\0', };
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 0;
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
		hash_data[w++] = 49 + i;	//0x00 + i

		if(!i) {
			for(int j = 0 ; j < 8 ; j++)
				hash_data[w++] = N[j];

			for(r = 0; r < data_size ; r++)
				hash_data[w++] = data[r];
		}

		w = 0;
		result = lsh_digest(algtype, hash_data, (9 + data_size) * 8, hash_result[i]);
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


lsh_err drbg_lsh_inner_output_gen(struct DRBG_LSH_Context *ctx, lsh_type algtype, lsh_u8 *output, int output_bits)
{
	lsh_err result;

	lsh_uint Block_Bit;
	lsh_uint n;

	lsh_uint *hash_data;
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 0, counter = 0;
	int flag = 0;
	int output_index = STATE_MAX_SIZE;

	if (ctx == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(algtype))
		Block_Bit = LSH256_HASH_VAL_MAX_BYTE_LEN * 8;
	else if(LSH_IS_LSH512(algtype))
		Block_Bit = LSH512_HASH_VAL_MAX_BYTE_LEN * 8;
	n = 2;

	for(int i = 0 ; i < n ; i++)
	{
		operation_add(ctx->working_state_V, STATE_MAX_SIZE, 0, i);
		r = LSH_GET_HASHBYTE(algtype) - 1;
		w = r;

		while(counter < LSH_GET_HASHBYTE(algtype))
		{
			hash_data[w--] = ctx->working_state_V[r--];
			counter++;
		}

		result = lsh_digest(algtype, hash_data, LSH_GET_HASHBYTE(algtype) * 8, hash_result[i]);
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

		output[w++] = hash_result[flag][r];
	}
}


lsh_err drbg_lsh_init(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size)
{
	lsh_err result;

	lsh_u8 input[1024] = {'\0', };

	int r, w, input_size;

	for(r = 0, w = 0 ; r < ent_size ; r++)
		input[w++] = entropy[r];

	for(r = 0 ; r < non_size ; r++)
		input[w++] = nonce[r];

	for(r = 0 ; r < per_size ; r++)
		input[w++] = per_string[r];
	input_size = ent_size + non_size + per_size;

	result = drbg_derivation_func(ctx, algtype, input, input_size, ctx->working_state_V);
	if (result != LSH_SUCCESS)
		return result;
	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = ctx->working_state_V[r];

	result = drbg_derivation_func(ctx, algtype, input, STATE_MAX_SIZE + 1, ctx->working_state_C);

	return result;
}


lsh_err drbg_lsh_reseed(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size)
{
	lsh_err result;

	lsh_u8 input[1024] = {'\0' ,};

	int r, w, input_size;

	input[0] = 0x01;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = ctx->working_state_V[r];

	for(r = 0 ; r < ent_size ; r++)
		input[w++] = entropy[r];

	for(r = 0 ; r < add_size ; r++)
		input[w++] = add_input[r];
	input_size = STATE_MAX_SIZE + ent_size + add_size + 1;

	result = drbg_derivation_func(ctx, algtype, input, input_size, ctx->working_state_V);
	if (result != LSH_SUCCESS)
		return result;
	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = ctx->working_state_V[r];

	result = drbg_derivation_func(ctx, algtype, input, STATE_MAX_SIZE + 1, ctx->working_state_C);
	if (result != LSH_SUCCESS)
		return result;

	return result;
}

lsh_err drbg_lsh_output_gen(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *add_input, int add_size, int output_bits, lsh_u8 *drbg)
{
	lsh_err result;

	lsh_u8 hash_data[1024] = {'\0', };
	int hash_data_size;
	lsh_u8 hash_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w;

	hash_data[0] = 0x02;
	for(r = 0 , w = 1 ; r < STATE_MAX_SIZE ; r++)
		hash_data[w++] = ctx->working_state_V[r];

	for(r = 0 ; r < add_size ; r++)
		hash_data[w++] = add_input[r];
	hash_data_size = STATE_MAX_SIZE + add_size + 1;

	result = lsh_digest(algtype, hash_data, hash_data_size * 8, hash_result);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = LSH_GET_HASHBYTE(algtype) - 1, start = 0 ; i > -1 ; i--)
		operation_add(ctx->working_state_V, STATE_MAX_SIZE, start++, hash_result[i]);
//////////////////////////////////////////////////////////////////////////////////

	hash_data[0] = 0x03;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		hash_data[w++] = ctx->working_state_V[r];
	hash_data_size = STATE_MAX_SIZE + 1;

	result = lsh_digest(algtype, hash_data, hash_data_size * 8, hash_result);
	if (result != LSH_SUCCESS)
		return result;

	/// add operation with C, V, reseed_counter ///

	/// call inner output gen func ///
	result = drbg_lsh_inner_output_gen(ctx, algtype, drbg, output_bits);

	return result;
}


lsh_err drbg_lsh_digest(lsh_type algtype, lsh_u8 *entropy, int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 *add_input, int add_size, int output_bits, lsh_u8 *drbg)
{
	struct DRBG_LSH_Context ctx;
	int result;

	result = drbg_lsh_init(&ctx, algtype, entropy, ent_size, nonce, non_size, per_string, per_size);
	if (result != LSH_SUCCESS)
		return result;

	result = drbg_lsh_reseed(&ctx, algtype, entropy, ent_size, add_input, add_size);
	if (result != LSH_SUCCESS)
		return result;

	result = drbg_lsh_output_gen(&ctx, algtype, add_input, add_size, output_bits, drbg);
	if (result != LSH_SUCCESS)
		return result;

	return result;
}
