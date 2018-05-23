/*
 * Copyright (c) 2016 NSR (National Security Research Institute)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 */

#include <string.h>
#include <math.h>
#include "../include/drbg.h"

lsh_err drbg_derivation_func(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *data)
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
		printf("%s \n", hash_data);
		result = lsh_digest(algtype, hash_data, strlen(hash_data) * 8, hash_result[i]);
		for(int j = 0 ; j < 28 ; j++)
		{
			printf("%02x", hash_result[i][j]);
		}
		printf("\n");
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

		ctx->working_state[w++] = hash_result[flag][i];
		printf("%02x", ctx->working_state[w-1]);
	}

	return result;
}

lsh_err drbg_lsh_inner_output_gen(struct DRBG_LSH_Context *ctx, lsh_type algtype)
{
	lsh_err result;

	lsh_uint Block_Bit;
	lsh_uint Seed_Bit;
	lsh_u8 N[8];
	lsh_uint len_seed;

	lsh_u8 hash_data[1024] = {'\0', };
	lsh_u8 hash_result[3][LSH512_HASH_VAL_MAX_BYTE_LEN];

	int r, w = 9;
	int block_size;
	int output_index = 55;

	if (ctx == NULL)
		return LSH_ERR_NULL_PTR;

	if(LSH_IS_LSH256(algtype))
	{
		Block_Bit = LSH256_MSG_BLK_BIT_LEN;
		block_size = LSH256_HASH_VAL_MAX_BYTE_LEN;
		Seed_Bit = 440;
		strcpy(N, "000001B8");
		len_seed = Seed_Bit / (LSH256_HASH_VAL_MAX_BYTE_LEN * 8);
	}
	else if(LSH_IS_LSH512(algtype))
	{
		Block_Bit = LSH512_MSG_BLK_BYTE_LEN;
		block_size = LSH512_HASH_VAL_MAX_BYTE_LEN;
		Seed_Bit = 888;
		strcpy(N, "00000378");
		len_seed = Seed_Bit / (LSH512_HASH_VAL_MAX_BYTE_LEN * 8);
	}
}



lsh_err drbg_lsh_digest(lsh_type algtype, lsh_u8 *data)
{
	struct DRBG_LSH_Context ctx;
	int result;

	result = drbg_derivation_func(&ctx, algtype, data);
	if (result != LSH_SUCCESS)
		return result;

	/*result = drbg_lsh_inner_output_gen(&ctx);
	if (result != LSH_SUCCESS)
		return result;*/

	return result;
}

/*

lsh_err hmac_lsh_init(struct HMAC_LSH_Context * ctx, lsh_type algtype, const lsh_u8 * key, size_t keybytelen){
	lsh_err result;

	lsh_u8 ipad[LSH512_MSG_BLK_BYTE_LEN];
	lsh_u8 tempKey[LSH512_HASH_VAL_MAX_BYTE_LEN];

	lsh_uint i;

	lsh_uint blockbytelen;

	if (ctx == NULL){
		return LSH_ERR_NULL_PTR;
	}

	if (LSH_IS_LSH256(algtype)){
		blockbytelen = LSH256_MSG_BLK_BYTE_LEN;
	}
	else{
		blockbytelen = LSH512_MSG_BLK_BYTE_LEN;
	}

	if (keybytelen > blockbytelen){
		result = lsh_init(&ctx->hash_ctx, algtype);
		if (result != LSH_SUCCESS){
			return result;
		}

		result = lsh_update(&ctx->hash_ctx, key, keybytelen * 8);
		if (result != LSH_SUCCESS){
			return result;
		}

		result = lsh_final(&ctx->hash_ctx, tempKey);
		if (result != LSH_SUCCESS){
			return result;
		}

		key = tempKey;
		keybytelen = LSH_GET_HASHBYTE(algtype);
	}

	for (i = 0; i < keybytelen; i++){
		ipad[i] = key[i] ^ 0x36;
		ctx->opad[i] = key[i] ^ 0x5c;
	}

	for (; i < blockbytelen; i++){
		ipad[i] = 0x36;
		ctx->opad[i] = 0x5c;
	}

	result = lsh_init(&ctx->hash_ctx, algtype);
	if (result != LSH_SUCCESS){
		return result;
	}

	result = lsh_update(&ctx->hash_ctx, ipad, blockbytelen * 8);
	if (result != LSH_SUCCESS){
		return result;
	}

	memset(ipad, 0, blockbytelen);
	return LSH_SUCCESS;

}

lsh_err hmac_lsh_update(struct HMAC_LSH_Context * ctx, const lsh_u8* data, size_t databytelen){
	if (ctx == NULL || data == NULL){
		return LSH_ERR_NULL_PTR;
	}

	return lsh_update(&ctx->hash_ctx, data, databytelen * 8);
	
}

lsh_err hmac_lsh_final(struct HMAC_LSH_Context * ctx, lsh_u8* digest){

	lsh_err result;
	lsh_type algtype;
	lsh_uint blockbytelen;

	if (ctx == NULL || digest == NULL){
		return LSH_ERR_NULL_PTR;
	}

	algtype = ctx->hash_ctx.algtype;
	result = lsh_final(&ctx->hash_ctx, digest);
	if (result != LSH_SUCCESS){
		return result;
	}

	if (LSH_IS_LSH256(algtype)){
		blockbytelen = LSH256_MSG_BLK_BYTE_LEN;
	}
	else{
		blockbytelen = LSH512_MSG_BLK_BYTE_LEN;
	}
	
	result = lsh_init(&ctx->hash_ctx, algtype);
	if (result != LSH_SUCCESS){
		return result;
	}

	result = lsh_update(&ctx->hash_ctx, ctx->opad, blockbytelen*8);
	memset(ctx->opad, 0, blockbytelen);
	if (result != LSH_SUCCESS){
		return result;
	}

	result = lsh_update(&ctx->hash_ctx, digest, LSH_GET_HASHBIT(algtype));
	if (result != LSH_SUCCESS){
		return result;
	}

	return lsh_final(&ctx->hash_ctx, digest);
}

lsh_err hmac_lsh_digest(lsh_type algtype, const lsh_u8* key, size_t keylen, const lsh_u8* data, size_t databytelen, lsh_u8* digest){
	struct HMAC_LSH_Context ctx;
	int result;

	result = hmac_lsh_init(&ctx, algtype, key, keylen);
	if (result != LSH_SUCCESS){
		return result;
	}

	result = hmac_lsh_update(&ctx, data, databytelen);
	if (result != LSH_SUCCESS){
		return result;
	}

	return hmac_lsh_final(&ctx, digest);
}
*/
