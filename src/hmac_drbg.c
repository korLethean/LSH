#include <string.h>
#include "../include/hmac.h"
#include "../include/hmac_drbg.h"

lsh_err hmac_drbg_lsh_update(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *data, int data_size, FILE *outf, bool tv)
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

	// Calculate V
	result = hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, ctx->working_state_V, ctx->output_bits / 8, ctx->working_state_V);
	if(result != LSH_SUCCESS)
			return result;

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

lsh_err hmac_drbg_lsh_reseed(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, FILE *outf, bool tv)
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

	result = hmac_drbg_lsh_update(ctx, seed_material, seed_size, outf, tv);
	if(result != LSH_SUCCESS)
		return result;

	ctx->reseed_counter = 1;

	if(!tv)
	{		//***** TEXT OUTPUT - entropy, Key, V (reseed function) *****//
		fprintf(outf, "entropy = ");
		for(int i = 0 ; i < ent_size; i++)
			fprintf(outf, "%02x", entropy[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d\n", ctx->reseed_counter);

		fprintf(outf, "\n");
	}

	ctx->setting.is_addinput_null = true;

	return result;
}

lsh_err hmac_drbg_lsh_init(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf, bool tv)
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

	if(!tv)
	{		//***** TEXT OUTPUT - Key, V (initial) *****//
		fprintf(outf, "K = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "V = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n\n");
	}

	ctx->reseed_counter = 1;

	result = hmac_drbg_lsh_update(ctx, seed_material, seed_size, outf, tv);
	if(result != LSH_SUCCESS)
		return result;

	if(!tv)
	{		//***** TEXT OUTPUT - Key, V, reseed_counter (after update) *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d\n\n", ctx->reseed_counter);
	}

	return result;
}

lsh_err hmac_drbg_lsh_output_gen(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int cycle, lsh_u8 *drbg, int *counter, FILE *outf, bool tv)
{
	lsh_err result;
	double n;
	lsh_u8 hmac_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];
	int flag = 0, w = 0;

	int output_index = ctx->output_bits * 2 / 8;

	if(!ctx->setting.using_addinput)
		ctx->setting.is_addinput_null = true;
	else if(add_size)
		ctx->setting.is_addinput_null = false;

	if(!tv)
	{		//***** TEXT OUTPUT - Key, V, add_input (before output gen) *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d\n", ctx->reseed_counter);
		if(ctx->setting.using_addinput)
		{
			fprintf(outf, "addInput = ");
			for(int i = 0 ; i < add_size; i++)
				fprintf(outf, "%02x", add_input[i]);
			fprintf(outf, "\n");
		}
		fprintf(outf, "\n");
	}

	if(tv)
	{
		if(ctx->setting.prediction_resistance)
		{
			result = hmac_drbg_lsh_reseed(ctx, entropy, ent_size, add_input, add_size, outf, false);
			if (result != LSH_SUCCESS)
				return result;
		}
		else if(ctx->reseed_counter > 1 && !ctx->setting.prediction_resistance)
		{	// test vector forced reseed
			result = hmac_drbg_lsh_reseed(ctx, entropy, ent_size, add_input + (add_size * 8), add_size, outf, false);
			if (result != LSH_SUCCESS)
				return result;
			if(add_size)
				ctx->setting.is_addinput_null = false;
		}

		if(!ctx->setting.is_addinput_null)
		{	// ****** inner reseed ****** //
			if(ctx->setting.using_addinput)
				result = hmac_drbg_lsh_update(ctx, add_input, add_size, outf, tv);
			else
				result = hmac_drbg_lsh_update(ctx, NULL, 0, outf, tv);

			if(result != LSH_SUCCESS)
				return result;

			if(!tv)
			{		//***** TEXT OUTPUT - Key, V, reseed_counter (after update) *****//
				fprintf(outf, "*K = ");
				for(int i = 0 ; i < ctx->output_bits / 8; i++)
					fprintf(outf, "%02x", ctx->working_state_Key[i]);
				fprintf(outf, "\n");
				fprintf(outf, "*V = ");
				for(int i = 0 ; i < ctx->output_bits / 8; i++)
					fprintf(outf, "%02x", ctx->working_state_V[i]);
				fprintf(outf, "\n");
				fprintf(outf, "*reseed_counter = %d\n\n", ctx->reseed_counter);
			}
		}
	}
	else
	{
		if(ctx->reseed_counter > ctx->setting.refresh_period || ctx->setting.prediction_resistance)
		{
			result = hmac_drbg_lsh_reseed(ctx, entropy, ent_size, add_input, add_size, outf, tv);
			if(result != LSH_SUCCESS)
				return result;
		}
		else if(!ctx->setting.is_addinput_null)
		{
			if(ctx->setting.using_addinput)
				result = hmac_drbg_lsh_update(ctx, add_input, add_size, outf, tv);
			else
				result = hmac_drbg_lsh_update(ctx, NULL, 0, outf, tv);

			if(result != LSH_SUCCESS)
				return result;

			if(!tv)
			{		//***** TEXT OUTPUT - Key, V, reseed_counter (after update) *****//
				fprintf(outf, "*K = ");
				for(int i = 0 ; i < ctx->output_bits / 8; i++)
					fprintf(outf, "%02x", ctx->working_state_Key[i]);
				fprintf(outf, "\n");
				fprintf(outf, "*V = ");
				for(int i = 0 ; i < ctx->output_bits / 8; i++)
					fprintf(outf, "%02x", ctx->working_state_V[i]);
				fprintf(outf, "\n");
				fprintf(outf, "*reseed_counter = %d\n\n", ctx->reseed_counter);
			}
		}
	}

	n = ceil((double) ctx->output_bits * 2 / (double) ctx->output_bits);

	for(int i = 0 ; i < (int) n ; i++)
	{
		result = hmac_lsh_digest(ctx->setting.drbgtype, ctx->working_state_Key, ctx->output_bits / 8, ctx->working_state_V, ctx->output_bits / 8, ctx->working_state_V);
		if(result != LSH_SUCCESS)
			return result;

		for(int r = 0 ; r < ctx->output_bits / 8; r++){
			if(r != output_index)
				drbg[w++] = ctx->working_state_V[r];
		}
		output_index -= ctx->output_bits / 8;
	}

	if(!tv)
	{		//***** TEXT OUTPUT - output(count) *****//
		printf("output%d = ", *counter); // console output
		fprintf(outf, "output%d = ", (*counter)++);
		for(int i = 0 ; i < ctx->output_bits * 2 / 8 ; i++)
		{
			printf("%02x", drbg[i]);	// console output
			fprintf(outf, "%02x", drbg[i]);
		}
		printf("\n");	// console output
		fprintf(outf, "\n\n");
	}

	if(!ctx->setting.is_addinput_null)
		result = hmac_drbg_lsh_update(ctx, add_input, add_size, outf, tv);
	else
		result = hmac_drbg_lsh_update(ctx, NULL, 0, outf, tv);

	if(result != LSH_SUCCESS)
		return result;

	ctx->reseed_counter += 1;

	if(!tv)
	{		//***** TEXT OUTPUT - Key, V, reseed_counter (after update) *****//
		fprintf(outf, "*K = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_Key[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*V = ");
		for(int i = 0 ; i < ctx->output_bits / 8; i++)
			fprintf(outf, "%02x", ctx->working_state_V[i]);
		fprintf(outf, "\n");
		fprintf(outf, "*reseed_counter = %d", ctx->reseed_counter);
	}

	return result;
}

lsh_err hmac_drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	struct HMAC_DRBG_LSH_Context ctx;
	int result;
	int counter = 1;

	ctx.output_bits = output_bits / 2;
	ctx.setting.drbgtype = algtype;
	ctx.setting.refresh_period = cycle;

	ctx.setting.prediction_resistance = true;	//예측내성
	ctx.setting.using_perstring = false;		//개별화
	ctx.setting.using_addinput = false;		//추가입력

/*	if(per_size != 0)
		ctx.setting.using_perstring = true;
	else
		ctx.setting.using_perstring = false;

	if(add_size != 0)
		ctx.setting.using_addinput = true;
	else
		ctx.setting.using_addinput = false;

	ctx.setting.prediction_resistance = false;*/

	result = hmac_drbg_lsh_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, outf, false);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx.setting.refresh_period + 1 ; i++)
	{
		if(ctx.setting.prediction_resistance || ctx.setting.refresh_period == 0)
			result = hmac_drbg_lsh_output_gen(&ctx, entropy[i+1], ent_size, add_input[i], add_size, cycle, drbg, &counter, outf, false);
		else
			result = hmac_drbg_lsh_output_gen(&ctx, entropy[i], ent_size, add_input[i], add_size, cycle, drbg, &counter, outf, false);
		if (result != LSH_SUCCESS)
			return result;

		if(i < ctx.setting.refresh_period)
			fprintf(outf, "\n\n");
	}

	return result;
}

lsh_err hmac_drbg_lsh_tv_pr_digest(lsh_type algtype, bool pr, lsh_u8 *ent1, lsh_u8 *ent2, lsh_u8 *ent3, int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 *add1, lsh_u8 *add2, int add_size, int output_bits, int cycle, lsh_u8 *drbg)
{
	struct HMAC_DRBG_LSH_Context ctx;
	lsh_err result;
	lsh_u8 *entropy[3] = {ent1, ent2, ent3};
	lsh_u8 *additional[2] = {add1, add2};

	int ent_byte = ent_size / 8;
	int non_byte = non_size / 8;
	int per_byte = per_size / 8;
	int add_byte = add_size / 8;

	int counter = 1;

	ctx.output_bits = output_bits / 2;
	ctx.setting.drbgtype = algtype;
	ctx.setting.refresh_period = cycle;

	ctx.setting.prediction_resistance = pr;	//예측내성
	if(per_size)
		ctx.setting.using_perstring = true;		//개별화
	else
		ctx.setting.using_perstring = false;
	if(add_size)
		ctx.setting.using_addinput = true;		//추가입력
	else
		ctx.setting.using_addinput = false;

	result = hmac_drbg_lsh_init(&ctx, entropy[0], ent_byte, nonce, non_byte, per_string, per_byte, NULL, true);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx.setting.refresh_period + 1 ; i++)
	{
		result = hmac_drbg_lsh_output_gen(&ctx, entropy[i+1], ent_byte, additional[i], add_byte, cycle, drbg, &counter, NULL, true);
		if (result != LSH_SUCCESS)
			return result;
	}

	return result;
}

lsh_err hmac_drbg_lsh_tv_no_pr_digest(lsh_type algtype, bool pr, lsh_u8 *ent, lsh_u8 *ent_re, int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 *add1, lsh_u8 *add_re, lsh_u8 *add2, int add_size, int output_bits, int cycle, lsh_u8 *drbg)
{
	struct HMAC_DRBG_LSH_Context ctx;
	lsh_err result;
	lsh_u8 *additional[3] = {add1, add2, add_re};

	int ent_byte = ent_size / 8;
	int non_byte = non_size / 8;
	int per_byte = per_size / 8;
	int add_byte = add_size / 8;

	int counter = 1;

	ctx.output_bits = output_bits / 2;
	ctx.setting.drbgtype = algtype;
	ctx.setting.refresh_period = cycle;

	ctx.setting.prediction_resistance = pr;	//예측내성
	if(per_size)
		ctx.setting.using_perstring = true;		//개별화
	else
		ctx.setting.using_perstring = false;
	if(add_size)
		ctx.setting.using_addinput = true;		//추가입력
	else
		ctx.setting.using_addinput = false;

	result = hmac_drbg_lsh_init(&ctx, ent, ent_byte, nonce, non_byte, per_string, per_byte, NULL, true);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx.setting.refresh_period + 1 ; i++)
	{
		result = hmac_drbg_lsh_output_gen(&ctx, ent_re, ent_byte, additional[i], add_byte, cycle, drbg, &counter, NULL, true);
		if (result != LSH_SUCCESS)
			return result;
	}

	return result;
}
