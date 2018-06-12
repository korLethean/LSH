#include <string.h>
#include "../include/drbg.h"

void hmac_operation_add(unsigned char *arr, int ary_size, int start_index, unsigned int num)
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

lsh_err hmac_drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf)
{
	struct DRBG_LSH_Context ctx;
	int result;

	ctx.setting.drbgtype = algtype;
	ctx.setting.refresh_period = 2;

	/*ctx.setting.prediction_resistance = false;	//예측내성
	ctx.setting.using_perstring = false;		//개별화
	ctx.setting.using_addinput = false;		//추가입력*/

	if(per_size != 0)
		ctx.setting.using_perstring = true;
	else
		ctx.setting.using_perstring = false;

	if(add_size != 0)
		ctx.setting.using_addinput = true;
	else
		ctx.setting.using_addinput = false;

	ctx.setting.prediction_resistance = false;

	//result = drbg_lsh_init(&ctx, entropy[0], ent_size, nonce, non_size, per_string, per_size, outf);
	if (result != LSH_SUCCESS)
		return result;

	for(int i = 0 ; i < ctx.setting.refresh_period + 1 ; i++)
	{
		/*if(ctx.setting.prediction_resistance || ctx.setting.refresh_period == 0)
			result = drbg_lsh_output_gen(&ctx, entropy[i+1], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);
		else
			result = drbg_lsh_output_gen(&ctx, entropy[i], ent_size, add_input[i], add_size, output_bits, cycle, drbg, outf);

		if (result != LSH_SUCCESS)
			return result;*/
	}
	return result;
}
