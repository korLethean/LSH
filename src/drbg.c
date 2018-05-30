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
		hash_data[1] = 0x00;
		hash_data[2] = 0x00;
		hash_data[3] = 0x01;
		hash_data[4] = 0xB8;	// N = 440
	}
	else if(LSH_IS_LSH512(algtype))
	{
		Block_Bit = LSH512_HASH_VAL_MAX_BYTE_LEN * 8;
		Seed_Bit = 888;
		hash_data[1] = 0x00;
		hash_data[2] = 0x00;
		hash_data[3] = 0x03;
		hash_data[4] = 0x78;	// N = 888
	}
	len_seed = ceil((double)Seed_Bit / (double)Block_Bit);

	for(int i = 0 ; i < len_seed ; i++)
	{
		hash_data[0] = i + 1;	// counter

		w = 5;
		if(!i) {
			for(r = 0; r < data_size ; r++)
				hash_data[w++] = data[r];
		}

		result = lsh_digest(algtype, hash_data, (5 + data_size) * 8, hash_result[i]);
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


lsh_err drbg_lsh_inner_output_gen(lsh_u8 *input, lsh_type algtype, lsh_u8 *output, int output_bits, FILE *outf)
{
	lsh_err result;

	lsh_uint Block_Bit;
	double n;

	lsh_u8 hash_data[64];
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 0, counter = 0;
	int flag = 0;
	int seed_bits;
	int output_index = output_bits / 8;

	if (input == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(algtype))
	{
		Block_Bit = LSH256_HASH_VAL_MAX_BYTE_LEN * 8;
		seed_bits = 440;
	}
	else if(LSH_IS_LSH512(algtype))
	{
		Block_Bit = LSH512_HASH_VAL_MAX_BYTE_LEN * 8;
		seed_bits = 888;
	}
	n = ceil((double) output_bits / (double) Block_Bit);

	for(int i = 0 ; i < (int)n ; i++)
	{
		operation_add(input, STATE_MAX_SIZE, 0, 1);
		for(r = STATE_MAX_SIZE - 1, w = Block_Bit / 8 - 1 ; w > -1 ; w-- )
			hash_data[w] = input[r--];

		printf("no. %d state V: ", i + 1);
		for(int a = 0 ; a < STATE_MAX_SIZE ; a++)
			printf("%02x", input[a]);
		printf("\n");
		printf("no. %d input data of hash: ", i + 1);
		for(int a = 0 ; a < Block_Bit / 8 ; a++)
			printf("%02x", hash_data[a]);
		printf("\n");

		result = lsh_digest(algtype, hash_data, Block_Bit, hash_result[i]);

		printf("no. %d hash: ", i + 1);
		for(int a = 0 ; a < LSH_GET_HASHBYTE(algtype) ; a++)
			printf("%02x", hash_result[i][a]);
		printf("\n");
	}

	printf("output1: ");
	w = 0;
	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == Block_Bit / 8)
		{
			flag += 1;
			output_index -= Block_Bit / 8;
			i = 0;
		}
		output[w++] = hash_result[flag][i];

		printf("%02x", output[w-1]);
	}
	printf("\n");

	return result;
}


lsh_err drbg_lsh_init(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf)
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

	{		//***** TEXT OUTPUT - V *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < input_size ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n\n");
	}
	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = ctx->working_state_V[r];

	result = drbg_derivation_func(ctx, algtype, input, STATE_MAX_SIZE + 1, ctx->working_state_C);
	if (result != LSH_SUCCESS)
			return result;

	{		//***** TEXT OUTPUT - C *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE + 1 ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_C[i]);
	}

	ctx->reseed_counter = 1;

	return result;
}


lsh_err drbg_lsh_reseed(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, FILE *outf)
{
	lsh_err result;

	lsh_u8 input[1024] = {'\0' ,};

	int r, w, input_size;

	{
		//***** TEXT OUTPUT - entropy *****//
		fprintf(outf, "entropy = ");
		for(int i = 0 ; i < ent_size ; i++)
			fprintf(outf, "%02x", entropy[i]);
		fprintf(outf, "\n\n");
	}

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

	{		//***** TEXT OUTPUT - V *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < input_size ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n\n");
	}

	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = ctx->working_state_V[r];

	result = drbg_derivation_func(ctx, algtype, input, STATE_MAX_SIZE + 1, ctx->working_state_C);
	if (result != LSH_SUCCESS)
		return result;

	{		//***** TEXT OUTPUT - C *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE + 1 ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_C[i]);
		fprintf(outf, "\n\n");
	}

	ctx->reseed_counter = 1;

	{		//***** TEXT OUTPUT - reseed_counter *****//
		fprintf(outf, "reseed_counter = %d\n\n", ctx->reseed_counter);
	}

	return result;
}


lsh_err drbg_lsh_output_gen(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	lsh_err result;

	lsh_u8 hash_data[1024] = {'\0', };
	int hash_data_size;
	lsh_u8 hash_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w;
	static int counter = 1;

	{		//***** TEXT OUTPUT - V C reseed_counter addInput *****//
		fprintf(outf, "\n\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");

		fprintf(outf, "C = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_C[i]);
		fprintf(outf, "\n");

		fprintf(outf, "reseed_counter = %d \n", ctx->reseed_counter);

		fprintf(outf, "addInput = ");
		for(int i = 0 ; i < add_size ; i++)
			fprintf(outf, "%02x", add_input[i]);
		fprintf(outf, "\n\n");
	}


	if(ctx->reseed_counter > cycle)
	{
		result = drbg_lsh_reseed(ctx, algtype, entropy, ent_size, add_input, add_size, outf);
		if (result != LSH_SUCCESS)
			return result;
	}
	else
	{	// ****** inner reseed ****** //
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

		{		//***** TEXT OUTPUT - w(hash) V *****//
			fprintf(outf, "w = ");
			for(int i = 0 ; i < LSH_GET_HASHBYTE(algtype) ; i++)
				fprintf(outf, "%02x", hash_result[i]);
			fprintf(outf, "\n");
			fprintf(outf, "V = ");
			for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
				fprintf(outf, "%02x", ctx->working_state_V[i]);
			fprintf(outf, "\n\n");
		}
	}

	result = drbg_lsh_inner_output_gen(ctx->working_state_V, algtype, drbg, output_bits, outf);

	{		//***** TEXT OUTPUT - output(count) *****//
		fprintf(outf, "output%d = ", counter++);
		for(int i = 0 ; i < output_bits / 8 ; i++)
			fprintf(outf, "%02x", drbg[i]);
		fprintf(outf, "\n\n");
	}

	hash_data[0] = 0x03;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		hash_data[w++] = ctx->working_state_V[r];
	hash_data_size = STATE_MAX_SIZE + 1;

	result = lsh_digest(algtype, hash_data, hash_data_size * 8, hash_result);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = LSH_GET_HASHBYTE(algtype) - 1, start = 0 ; i > -1 ; i--)
		operation_add(ctx->working_state_V, STATE_MAX_SIZE, start++, hash_result[i]);

	for(int i = STATE_MAX_SIZE - 1, start = 0 ; i > -1 ; i--)
		operation_add(ctx->working_state_V, STATE_MAX_SIZE, start++, ctx->working_state_C[i]);

	operation_add(ctx->working_state_V, STATE_MAX_SIZE, 0, ctx->reseed_counter);

	{		//***** TEXT OUTPUT - w(hash) V (after inner reseed) *****//
		fprintf(outf, "w = ");
		for(int i = 0 ; i < LSH_GET_HASHBYTE(algtype) ; i++)
			fprintf(outf, "%02x", hash_result[i]);
		fprintf(outf, "\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");
	}

	ctx->reseed_counter += 1;

	{		//***** TEXT OUTPUT - reseed_counter *****//
		fprintf(outf, "reseed_counter = %d", ctx->reseed_counter);
	}

	return result;
}


lsh_err drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	struct DRBG_LSH_Context ctx;
	int result;

	result = drbg_lsh_init(&ctx, algtype, entropy[0], ent_size, nonce, non_size, per_string, per_size, outf);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < cycle + 1 ; i++)
	{
		result = drbg_lsh_output_gen(&ctx, algtype, entropy[i], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);
		if (result != LSH_SUCCESS)
			return result;
	}

	return result;
}
