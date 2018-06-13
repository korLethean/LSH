#include <string.h>
#include "../include/hmac.h"
#include "../include/hmac_drbg.h"

void hmac_drbg_operation_add(unsigned char *arr, int ary_size, int start_index, unsigned int num)
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

lsh_err hmac_drbg_lsh_update(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *data, int data_size)
{
	lsh_err result;
	lsh_u8 input_data[512];
	lsh_uint input_data_size = 0;
	int w = 0;

	for(int i = 0 ; i < ctx->output_bits / 8 ; i++)
		input_data[w++] = ctx->working_state_V[i];
	input_data_size += ctx->output_bits / 8;

	input_data[w++] = 0;
	input_data_size += 1;

	if(data_size)
	{
		for(int i = 0 ; i < data_size ; i++)
			input_data[w++] = data[i];
		input_data_size += data_size;
	}

	// Calculate Key
	result = hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, input_data, input_data_size, ctx->working_state_Key);
	if(result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx->output_bits / 8 ; i++)
		printf("%02x", ctx->working_state_Key[i]);
	printf("\n");
	// Calculate V
	hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, ctx->working_state_V, ctx->output_bits / 8, ctx->working_state_V);
	if(result != LSH_SUCCESS)
			return result;

	for(int i = 0 ; i < ctx->output_bits / 8 ; i++)
		printf("%02x", ctx->working_state_V[i]);
	printf("\n");

	if(data_size)
	{
		w = 0;

		for(int i = 0 ; i < ctx->output_bits / 8 ; i++)
			input_data[w++] = ctx->working_state_V[i];

		input_data[w++] = 1;

		for(int i = 0 ; i < data_size ; i++)
			input_data[w++] = data[i];

		result = hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, input_data, input_data_size, ctx->working_state_Key);
		if(result != LSH_SUCCESS)
				return result;

		result = hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, ctx->working_state_V, ctx->output_bits / 8, ctx->working_state_V);
		if(result != LSH_SUCCESS)
				return result;
	}

	return result;
}

lsh_err hmac_drbg_lsh_reseed(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, FILE *outf)
{
	lsh_err result;
	lsh_u8 seed_material[512];
	lsh_uint seed_size = 0;
	int w = 0;

	for(int i = 0 ; i < ent_size ; i++)
		seed_material[w++] = entropy[i];
	seed_size += ent_size;

	if(ctx->setting.using_addinput)
	{
		for(int i = 0 ; i < add_size ; i++)
			seed_material[w++] = add_input[i];
		seed_size += add_size;
	}

	result = hmac_drbg_lsh_update(ctx, seed_material, seed_size);
	if(result != LSH_SUCCESS)
		return result;

	ctx->reseed_counter = 1;

	if(!ctx->setting.prediction_resistance)
		ctx->setting.using_addinput = false;

	return result;
}

lsh_err hmac_drbg_lsh_init(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf)
{
	lsh_err result;
	lsh_u8 seed_material[512];
	lsh_uint seed_size = 0;
	int w = 0;

	for(int i = 0 ; i < ent_size ; i++)
		seed_material[w++] = entropy[i];
	seed_size += ent_size;

	for(int i = 0 ; i < non_size ; i++)
		seed_material[w++] = nonce[i];
	seed_size += non_size;

	{		//***** TEXT OUTPUT - w(hash) V (after inner reseed) *****//
		fprintf(outf, "K = ");
		for(int i = 0 ; i < ctx->output_bits; i++)
			fprintf(outf, "%02x", ctx->working_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < ctx->output_bits; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");
	}


	if(ctx->setting.using_perstring)
	{
		for(int i = 0 ; i < per_size ; i++)
			seed_material[w++] = per_string[i];
		seed_size += per_size;
	}

	for(int i = 0 ; i < ctx->output_bits / 8 ; i++)
	{
		ctx->working_state_Key[i] = 0;
		ctx->working_state_V[i] = 1;
	}

	result = hmac_drbg_lsh_update(ctx, seed_material, seed_size);
	if(result != LSH_SUCCESS)
		return result;

	ctx->reseed_counter = 1;

	return result;
}

lsh_err hmac_drbg_lsh_output_gen(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int cycle, lsh_u8 *drbg, FILE *outf)
{
	lsh_err result;
	double n;
	lsh_u8 hmac_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];
	int flag = 0, w = 0;

	int output_index = ctx->output_bits * 2 / 8;


	if(ctx->reseed_counter > ctx->setting.refresh_period || ctx->setting.prediction_resistance)
	{
		result = hmac_drbg_lsh_reseed(ctx, entropy, ent_size, add_input, add_size, outf);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(ctx->setting.using_addinput)
	{
		result = hmac_drbg_lsh_update(ctx, add_input, add_size);
		if(result != LSH_SUCCESS)
			return result;
	}

	n = ceil((double) ctx->output_bits * 2 / (double) ctx->output_bits);

	for(int i = 0 ; i < (int) n ; i++)
	{
		result = hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, ctx->working_state_V, ctx->output_bits / 8, hmac_result[i]);
		if(result != LSH_SUCCESS)
			return result;
	}

	for(int i = 0 ; i < output_index ; i++)
	{
		if(i == ctx->output_bits / 8)
		{
			flag += 1;
			output_index -= ctx->output_bits / 8;
			i = 0;
		}

		drbg[w++] = hmac_result[flag][i];
	}

	result = hmac_drbg_lsh_update(ctx, add_input, add_size);
	if(result != LSH_SUCCESS)
		return result;

	ctx->reseed_counter += 1;

	return result;
}

lsh_err hmac_drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	struct HMAC_DRBG_LSH_Context ctx;
	int result;

	ctx.output_bits = output_bits / 2;
	ctx.setting.drbgtype = algtype;
	ctx.setting.refresh_period = cycle;

	ctx.setting.prediction_resistance = false;	//예측내성
	ctx.setting.using_perstring = true;		//개별화
	ctx.setting.using_addinput = true;		//추가입력


/*	if(per_size != 0)
		ctx.setting.using_perstring = true;
	else
		ctx.setting.using_perstring = false;

	if(add_size != 0)
		ctx.setting.using_addinput = true;
	else
		ctx.setting.using_addinput = false;

	ctx.setting.prediction_resistance = false;*/

	result = hmac_drbg_lsh_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, outf);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx.setting.refresh_period + 1 ; i++)
	{
		if(ctx.setting.prediction_resistance || ctx.setting.refresh_period == 0)
			result = hmac_drbg_lsh_output_gen(&ctx, entropy[i+1], ent_size, add_input[i], add_size, cycle, drbg, outf);
		else
			result = hmac_drbg_lsh_output_gen(&ctx, entropy[i], ent_size, add_input[i], add_size, cycle, drbg, outf);

		if (result != LSH_SUCCESS)
			return result;
	}

	return result;
}
