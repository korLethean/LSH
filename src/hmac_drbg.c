#include <string.h>
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

	return result;
}

lsh_err hmac_drbg_lsh_init(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf)
{
	lsh_err result = LSH_SUCCESS;
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

	result = hmac_drbg_lsh_update(ctx, seed_material, seed_size);

	return result;
}

lsh_err hmac_drbg_lsh_reseed(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, FILE *outf)
{
	lsh_err result;

	return result;
}

lsh_err hmac_drbg_lsh_output_gen(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int cycle, lsh_u8 *drbg, FILE *outf)
{
	lsh_err result;

	return result;
}

lsh_err hmac_drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	struct HMAC_DRBG_LSH_Context ctx;
	int result;

	ctx.output_bits = output_bits;
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

/*	for(int i = 0 ; i < ctx.setting.refresh_period + 1 ; i++)
	{
		if(ctx.setting.prediction_resistance || ctx.setting.refresh_period == 0)
			result = drbg_lsh_output_gen(&ctx, entropy[i+1], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);
		else
			result = drbg_lsh_output_gen(&ctx, entropy[i], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);

		if (result != LSH_SUCCESS)
			return result;
	}*/

	return result;
}
