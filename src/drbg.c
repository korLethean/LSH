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


lsh_err drbg_derivation_func(struct DRBG_LSH_Context *ctx, const lsh_u8 *data, int data_size, lsh_u8 *output)
{
	lsh_err result;

	lsh_uint Block_Bit;
	lsh_uint Seed_Bit;
	lsh_uint len_seed;

	lsh_u8 hash_data[512] = {'\0', };
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN] = {'\0',};

	int r, w = 0;
	int flag = 0;
	int output_index;

	if (ctx == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(ctx->setting.drbgtype))
	{
		Block_Bit = LSH_GET_HASHBIT(ctx->setting.drbgtype);
		Seed_Bit = 440;
		hash_data[1] = 0x00;
		hash_data[2] = 0x00;
		hash_data[3] = 0x01;
		hash_data[4] = 0xB8;	// N = 440
		output_index = STATE_MAX_SIZE_256;
	}
	else if(LSH_IS_LSH512(ctx->setting.drbgtype))
	{
		if(ctx->setting.drbgtype == LSH_TYPE_384 || ctx->setting.drbgtype == LSH_TYPE_512)
		{
			Block_Bit = LSH_GET_HASHBIT(ctx->setting.drbgtype);
			Seed_Bit = 888;
			hash_data[1] = 0x00;
			hash_data[2] = 0x00;
			hash_data[3] = 0x03;
			hash_data[4] = 0x78;	// N = 888
			output_index = STATE_MAX_SIZE_512;
		}
		else
		{
			Block_Bit = LSH_GET_HASHBIT(ctx->setting.drbgtype);
			Seed_Bit = 440;
			hash_data[1] = 0x00;
			hash_data[2] = 0x00;
			hash_data[3] = 0x01;
			hash_data[4] = 0xB8;	// N = 440
			output_index = STATE_MAX_SIZE_256;
		}
	}
	len_seed = ceil((double)Seed_Bit / (double)Block_Bit);

	hash_data[0] = 1;	// counter

	for(int i = 0 ; i < len_seed ; i++)
	{
		w = 5;
		if(!i) {
			for(r = 0; r < data_size ; r++)
				hash_data[w++] = data[r];
		}
		else
			hash_data[0]++;

		result = lsh_digest(ctx->setting.drbgtype, hash_data, (5 + data_size) * 8, hash_result[i]);
	}

	w = 0;
	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == LSH_GET_HASHBYTE(ctx->setting.drbgtype))
		{
			flag += 1;
			output_index -= LSH_GET_HASHBYTE(ctx->setting.drbgtype);
			i = 0;
		}

		output[w++] = hash_result[flag][i];
	}

	return result;
}


lsh_err drbg_lsh_inner_output_gen(struct DRBG_LSH_Context *ctx, lsh_u8 *input, lsh_u8 *output, int output_bits, FILE *outf)
{
	lsh_err result;

	lsh_uint Block_Bit;
	double n;
	int loop_count;

	lsh_u8 hash_data[111];
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 0, counter = 0;
	int flag = 0;
	int seed_bits;
	int output_index = output_bits / 8;

	int STATE_MAX_SIZE;

	if (input == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(ctx->setting.drbgtype))
	{
		Block_Bit = LSH_GET_HASHBYTE(ctx->setting.drbgtype) * 8;
		seed_bits = 440;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(LSH_IS_LSH512(ctx->setting.drbgtype))
	{
		if(ctx->setting.drbgtype == LSH_TYPE_384 || ctx->setting.drbgtype == LSH_TYPE_512)
		{
			Block_Bit = LSH_GET_HASHBYTE(ctx->setting.drbgtype) * 8;
			seed_bits = 888;
			STATE_MAX_SIZE = STATE_MAX_SIZE_512;
		}
		else
		{
			Block_Bit = LSH_GET_HASHBYTE(ctx->setting.drbgtype) * 8;
			seed_bits = 440;
			STATE_MAX_SIZE = STATE_MAX_SIZE_256;
		}
	}
	n = ceil((double) output_bits / (double) Block_Bit);

	for(int a = 0 ; a < STATE_MAX_SIZE ; a++)
		hash_data[a] = input[a];

	for(int i = 0 ; i < (int) n ; i++)
	{
		operation_add(hash_data, STATE_MAX_SIZE, 0, i);

		result = lsh_digest(ctx->setting.drbgtype, hash_data, STATE_MAX_SIZE * 8, hash_result[i]);
	}

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
	}

	return result;
}


lsh_err drbg_lsh_init(struct DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf)
{
	lsh_err result;

	lsh_u8 input[1024] = {'\0', };
	lsh_u8 *target_state_V;
	lsh_u8 *target_state_C;

	int r, w;
	int input_size = 0;
	int STATE_MAX_SIZE;

	if(LSH_IS_LSH256(ctx->setting.drbgtype))
	{
		target_state_V = ctx->working_state_V256;
		target_state_C = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(LSH_IS_LSH512(ctx->setting.drbgtype))
	{
		if(ctx->setting.drbgtype == LSH_TYPE_384 || ctx->setting.drbgtype == LSH_TYPE_512)
		{
			target_state_V = ctx->working_state_V512;
			target_state_C = ctx->working_state_C512;
			STATE_MAX_SIZE = STATE_MAX_SIZE_512;
		}
		else
		{
			target_state_V = ctx->working_state_V256;
			target_state_C = ctx->working_state_C256;
			STATE_MAX_SIZE = STATE_MAX_SIZE_256;
		}
	}

	for(r = 0, w = 0 ; r < ent_size ; r++)
		input[w++] = entropy[r];

	for(r = 0 ; r < non_size ; r++)
		input[w++] = nonce[r];

	if(ctx->setting.usingperstring)
	{
		for(r = 0 ; r < per_size ; r++)
			input[w++] = per_string[r];
		input_size += per_size;
	}
	input_size += ent_size + non_size;

	result = drbg_derivation_func(ctx, input, input_size, target_state_V);
	if (result != LSH_SUCCESS)
		return result;

	{		//***** TEXT OUTPUT - V *****//
		fprintf(outf, "init \n");
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < input_size ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n\n");
	}
	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = target_state_V[r];

	result = drbg_derivation_func(ctx, input, STATE_MAX_SIZE + 1, target_state_C);
	if (result != LSH_SUCCESS)
			return result;

	{		//***** TEXT OUTPUT - C *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE + 1 ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_C[i]);
	}

	ctx->reseed_counter = 1;

	return result;
}


lsh_err drbg_lsh_reseed(struct DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, FILE *outf)
{
	lsh_err result;

	lsh_u8 input[1024] = {'\0' ,};
	lsh_u8 *target_state_V;
	lsh_u8 *target_state_C;

	int r, w;
	int input_size = 0;
	int STATE_MAX_SIZE;

	if(LSH_IS_LSH256(ctx->setting.drbgtype))
	{
		target_state_V = ctx->working_state_V256;
		target_state_C = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(LSH_IS_LSH512(ctx->setting.drbgtype))
	{
		if(ctx->setting.drbgtype == LSH_TYPE_384 || ctx->setting.drbgtype == LSH_TYPE_512)
		{
			target_state_V = ctx->working_state_V512;
			target_state_C = ctx->working_state_C512;
			STATE_MAX_SIZE = STATE_MAX_SIZE_512;
		}
		else
		{
			target_state_V = ctx->working_state_V256;
			target_state_C = ctx->working_state_C256;
			STATE_MAX_SIZE = STATE_MAX_SIZE_256;
		}
	}

	{
		//***** TEXT OUTPUT - entropy *****//
		fprintf(outf, "entropy = ");
		for(int i = 0 ; i < ent_size ; i++)
			fprintf(outf, "%02x", entropy[i]);
		fprintf(outf, "\n\n");
	}

	input[0] = 0x01;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = target_state_V[r];

	for(r = 0 ; r < ent_size ; r++)
		input[w++] = entropy[r];

	if(ctx->setting.usingaddinput)
	{
		for(r = 0 ; r < add_size ; r++)
			input[w++] = add_input[r];
		input_size += add_size;
	}
	input_size += STATE_MAX_SIZE + ent_size + 1;

	result = drbg_derivation_func(ctx, input, input_size, target_state_V);
	if (result != LSH_SUCCESS)
		return result;

	{		//***** TEXT OUTPUT - V *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < input_size ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n\n");
	}

	memset(input, 0x00, 1024);

	input[0] = 0x00;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		input[w++] = target_state_V[r];

	result = drbg_derivation_func(ctx, input, STATE_MAX_SIZE + 1, target_state_C);
	if (result != LSH_SUCCESS)
		return result;

	{		//***** TEXT OUTPUT - C *****//
		fprintf(outf, "dfInput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE + 1 ; i++)
			fprintf(outf, "%02x", input[i]);
		fprintf(outf, "\n");
		fprintf(outf, "dfOutput = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_C[i]);
		fprintf(outf, "\n\n");
	}

	ctx->reseed_counter = 1;
	ctx->setting.usingaddinput = false;

	{		//***** TEXT OUTPUT - reseed_counter *****//
		fprintf(outf, "reseed_counter = %d\n\n", ctx->reseed_counter);
	}

	return result;
}


lsh_err drbg_lsh_output_gen(struct DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	lsh_err result;

	lsh_u8 hash_data[1024] = {'\0', };
	int hash_data_size;
	lsh_u8 hash_result[LSH512_HASH_VAL_MAX_BYTE_LEN];
	lsh_u8 *target_state_V;
	lsh_u8 *target_state_C;

	int r, w;
	int STATE_MAX_SIZE;

	static int counter = 1;

	if(LSH_IS_LSH256(ctx->setting.drbgtype))
	{
		target_state_V = ctx->working_state_V256;
		target_state_C = ctx->working_state_C256;
		STATE_MAX_SIZE = STATE_MAX_SIZE_256;
	}
	else if(LSH_IS_LSH512(ctx->setting.drbgtype))
	{
		if(ctx->setting.drbgtype == LSH_TYPE_384 || ctx->setting.drbgtype == LSH_TYPE_512)
		{
			target_state_V = ctx->working_state_V512;
			target_state_C = ctx->working_state_C512;
			STATE_MAX_SIZE = STATE_MAX_SIZE_512;
		}
		else
		{
			target_state_V = ctx->working_state_V256;
			target_state_C = ctx->working_state_C256;
			STATE_MAX_SIZE = STATE_MAX_SIZE_256;
		}
	}

	{		//***** TEXT OUTPUT - V C reseed_counter addInput *****//
		fprintf(outf, "\n\n");
		fprintf(outf, "%d reseed \n", ctx->reseed_counter);
		fprintf(outf, "V = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");

		fprintf(outf, "C = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_C[i]);
		fprintf(outf, "\n");

		fprintf(outf, "reseed_counter = %d \n", ctx->reseed_counter);

		if(ctx->setting.usingaddinput)
		{
			fprintf(outf, "addInput = ");
			for(int i = 0 ; i < add_size ; i++)
				fprintf(outf, "%02x", add_input[i]);
			fprintf(outf, "\n");
		}
		fprintf(outf, "\n");
	}


	if(ctx->reseed_counter > ctx->setting.refreshperiod || ctx->setting.predicttolerance)
	{
		result = drbg_lsh_reseed(ctx, entropy, ent_size, add_input, add_size, outf);
		if (result != LSH_SUCCESS)
			return result;
	}
	else if(ctx->setting.usingaddinput)
	{	// ****** inner reseed ****** //
		printf("inner \n");
		hash_data[0] = 0x02;
		for(r = 0 , w = 1 ; r < STATE_MAX_SIZE ; r++)
			hash_data[w++] = target_state_V[r];

		for(r = 0 ; r < add_size ; r++)
			hash_data[w++] = add_input[r];
		hash_data_size = STATE_MAX_SIZE + add_size + 1;

		result = lsh_digest(ctx->setting.drbgtype, hash_data, hash_data_size * 8, hash_result);
		if (result != LSH_SUCCESS)
			return result;

		for(int i = LSH_GET_HASHBYTE(ctx->setting.drbgtype) - 1, start = 0 ; i > -1 ; i--)
			operation_add(target_state_V, STATE_MAX_SIZE, start++, hash_result[i]);

		{		//***** TEXT OUTPUT - w(hash) V *****//
			fprintf(outf, "w = ");
			for(int i = 0 ; i < LSH_GET_HASHBYTE(ctx->setting.drbgtype) ; i++)
				fprintf(outf, "%02x", hash_result[i]);
			fprintf(outf, "\n");
			fprintf(outf, "V = ");
			for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
				fprintf(outf, "%02x", target_state_V[i]);
			fprintf(outf, "\n\n");
		}
	}

	result = drbg_lsh_inner_output_gen(ctx, target_state_V, drbg, output_bits, outf);

	{		//***** TEXT OUTPUT - output(count) *****//
		fprintf(outf, "%d gen \n", ctx->reseed_counter);
		printf("output%d = ", counter); // console output
		fprintf(outf, "output%d = ", counter++);
		for(int i = 0 ; i < output_bits / 8 ; i++)
		{
			printf("%02x", drbg[i]);	// console output
			fprintf(outf, "%02x", drbg[i]);
		}
		printf("\n");	// console output
		fprintf(outf, "\n\n");
	}

	hash_data[0] = 0x03;
	for(r = 0, w = 1 ; r < STATE_MAX_SIZE ; r++)
		hash_data[w++] = target_state_V[r];
	hash_data_size = STATE_MAX_SIZE + 1;

	result = lsh_digest(ctx->setting.drbgtype, hash_data, hash_data_size * 8, hash_result);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = LSH_GET_HASHBYTE(ctx->setting.drbgtype) - 1, start = 0 ; i > -1 ; i--)
		operation_add(target_state_V, STATE_MAX_SIZE, start++, hash_result[i]);

	for(int i = STATE_MAX_SIZE - 1, start = 0 ; i > -1 ; i--)
		operation_add(target_state_V, STATE_MAX_SIZE, start++, target_state_C[i]);

	operation_add(target_state_V, STATE_MAX_SIZE, 0, ctx->reseed_counter);

	ctx->reseed_counter += 1;

	{		//***** TEXT OUTPUT - w(hash) V (after inner reseed) *****//
		fprintf(outf, "w = ");
		for(int i = 0 ; i < LSH_GET_HASHBYTE(ctx->setting.drbgtype) ; i++)
			fprintf(outf, "%02x", hash_result[i]);
		fprintf(outf, "\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_V[i]);
		fprintf(outf, "\n");

		fprintf(outf, "C = ");		// TEMP TEXT OUTPUT//
		for(int i = 0 ; i < STATE_MAX_SIZE ; i++)
			fprintf(outf, "%02x", target_state_C[i]);
		fprintf(outf, "\n");
	}

	{		//***** TEXT OUTPUT - reseed_counter *****//
		fprintf(outf, "reseed_counter = %d", ctx->reseed_counter);
	}

	return result;
}


lsh_err drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	struct DRBG_LSH_Context ctx;
	int result;

	ctx.setting.drbgtype = algtype;
	ctx.setting.refreshperiod = cycle;

	if(per_size != 0)
		ctx.setting.usingperstring = true;
	else
		ctx.setting.usingperstring = false;

	if(add_size != 0)
		ctx.setting.usingaddinput = true;
	else
		ctx.setting.usingaddinput = false;

	ctx.setting.predicttolerance = false;

	result = drbg_lsh_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, outf);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx.setting.refreshperiod + 1 ; i++)
	{
		if(ctx.setting.predicttolerance)
			result = drbg_lsh_output_gen(&ctx, entropy[i+1], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);
		else
			result = drbg_lsh_output_gen(&ctx, entropy[i], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);

		if (result != LSH_SUCCESS)
			return result;
	}

	return result;
}
