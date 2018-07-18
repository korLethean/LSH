/*
 * hmac_pbkdf.c
 *
 *  Created on: 2018. 6. 26.
 *      Author: HD
 */

#include <stdio.h>
#include "../include/hmac_pbkdf.h"

lsh_err hmac_kdf_ctr_digest(lsh_type algtype, int loop_count, int byte_r, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int ct_len, lsh_uint len, lsh_uint hash_len, lsh_u8 *output, FILE *fp)
{
	lsh_err result;
	lsh_u8 *input;
	lsh_u8 *k_temp;

	int input_size;
	int temp_index = 0;
	int result_index = 0;
	int len_to_hex = len * 8;

	input_size = byte_r + label_len + ct_len + 3;	// 3 = 0x00(1) || [L]2(2)

	input = (lsh_u8*) malloc(sizeof(lsh_u8) * input_size);
	k_temp = (lsh_u8*) malloc(sizeof(lsh_u8) * hash_len);
	for(int i = 0 ; i < input_size ; i++)
		input[i] = '\0';	// initializing input

	temp_index = byte_r;
	for(int i = 0 ; i < label_len ; i++)
		input[temp_index++] = label[i];	// || label
	input[temp_index++] = 0;			// || 0x00
	for(int i = 0 ; i < ct_len ; i++)
		input[temp_index++] = context[i];//|| context
	input[temp_index + 1] = len_to_hex % 256;
	len_to_hex /= 256;
	input[temp_index] = len_to_hex % 256;	// || [L]2

	for(int i = 0 ; i < loop_count ; i++)
	{
		if(byte_r)							// || [i]2
		{
			for(temp_index = 0 ; temp_index < byte_r - 1; temp_index++)
				input[temp_index] = 0;
			input[temp_index] = i + 1;
		}

		printf("input %d size data: ", input_size);
		for(int j = 0 ; j < input_size ; j++)
			printf("%02x", input[j]);
		printf("\n");

		result = hmac_lsh_digest(algtype, Ki, Ki_len, input, input_size, k_temp);
		if(result != LSH_SUCCESS)
			return result;

		printf("output data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", k_temp[j]);
		printf("\n");

		fprintf(fp, "Input = ");
		for(int k = 0 ; k < input_size ; k++)
			fprintf(fp, "%02x", input[k]);
		fprintf(fp, "\n");
		fprintf(fp, "Result = ");
		for(int k = 0 ; k < hash_len ; k++)
			fprintf(fp, "%02x", k_temp[k]);
		fprintf(fp, "\n\n");

		for(int j = 0 ; j < hash_len ; j++)
		{
			if(result_index == len)
				break;
			output[result_index++] = k_temp[j];
		}
	}

	printf("final output: ");
	for(int i = 0 ; i < len ; i++)
		printf("%02x", output[i]);
	printf("\n");

	free(input);
	free(k_temp);

	return result;
}

lsh_err hmac_kdf_fb_digest(lsh_type algtype, int loop_count, int byte_r, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int ct_len, lsh_uint len, lsh_uint hash_len, lsh_u8 *output, FILE *fp)
{
	lsh_err result;
	lsh_u8 *input;
	lsh_u8 *k_temp;

	int input_size;
	int temp_index = 0;
	int result_index = 0;
	int len_to_hex = len * 8;

	input_size = byte_r + hash_len + label_len + ct_len + 3;	// 3 = 0x00(1) || [L]2(2)

	input = (lsh_u8*) malloc(sizeof(lsh_u8) * input_size);
	k_temp = (lsh_u8*) malloc(sizeof(lsh_u8) * hash_len);
	for(int i = 0 ; i < input_size ; i++)
		input[i] = '\0';	// initializing input
	for(int i = 0 ; i < hash_len ; i++)
		k_temp[i] = '\0';		// initailizing key

	temp_index = hash_len;				// skip k-size array
	if(byte_r)							// skip array when r != 0
		temp_index += byte_r;
	for(int i = 0 ; i < label_len ; i++)
		input[temp_index++] = label[i];	// || label
	input[temp_index++] = 0;			// || 0x00
	for(int i = 0 ; i < ct_len ; i++)
		input[temp_index++] = context[i];//|| context
	input[temp_index + 1] = len_to_hex % 256;
	len_to_hex /= 256;
	input[temp_index] = len_to_hex % 256;	// || [L]2

	for(int i = 0 ; i < loop_count ; i++)
	{
		temp_index = 0;
		for(int j = 0 ; j < hash_len ; j++)
			input[temp_index++] = k_temp[j];	// feedback Ki
		if(byte_r)								// || [i]2
		{
			for(temp_index = hash_len ; temp_index < byte_r - 1; temp_index++)
				input[temp_index] = 0;
			input[temp_index] = i + 1;
		}

		printf("input %d size data: ", input_size);
		for(int j = 0 ; j < input_size ; j++)
			printf("%02x", input[j]);
		printf("\n");

		result = hmac_lsh_digest(algtype, Ki, Ki_len, input, input_size, k_temp);
		if(result != LSH_SUCCESS)
			return result;

		printf("output data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", k_temp[j]);
		printf("\n");

		fprintf(fp, "Input = ");
		for(int k = 0 ; k < input_size ; k++)
			fprintf(fp, "%02x", input[k]);
		fprintf(fp, "\n");
		fprintf(fp, "Result = ");
		for(int k = 0 ; k < hash_len ; k++)
			fprintf(fp, "%02x", k_temp[k]);
		fprintf(fp, "\n\n");

		for(int j = 0 ; j < hash_len ; j++)
		{
			if(result_index == len)
				break;
			output[result_index++] = k_temp[j];
		}
	}

	printf("final output: ");
	for(int i = 0 ; i < len ; i++)
		printf("%02x", output[i]);
	printf("\n");

	free(input);
	free(k_temp);

	return result;
}

lsh_err hmac_kdf_dp_digest(lsh_type algtype, int loop_count, int byte_r, lsh_u8 *Ki, int Ki_len, lsh_u8 *label, int label_len, lsh_u8 *context, int ct_len, lsh_uint len, lsh_uint hash_len, lsh_u8 *output, FILE *fp)
{
	lsh_err result;
	lsh_u8 *input;
	lsh_u8 *k_temp;
	lsh_u8 *a_temp;

	int input_size;
	int a_size;
	int temp_index = 0;
	int a_index = 0;
	int result_index = 0;
	int len_to_hex = len * 8;

	a_size = label_len + ct_len + 3;		// 3 = 0x00(1) || [L]2(2)
	input_size = byte_r + hash_len + label_len + ct_len + 3;	// 3 = 0x00(1) || [L]2(2)

	input = (lsh_u8*) malloc(sizeof(lsh_u8) * input_size);
	k_temp = (lsh_u8*) malloc(sizeof(lsh_u8) * hash_len);
	a_temp = (lsh_u8*) malloc(sizeof(lsh_u8) * hash_len);
	for(int i = 0 ; i < input_size ; i++)
		input[i] = '\0';	// initializing input

	temp_index = hash_len;				// skip a-size array
	if(byte_r)							// skip array when r != 0
		temp_index += byte_r;
	for(int i = 0 ; i < label_len ; i++)
	{
		a_temp[a_index++] = label[i];
		input[temp_index++] = label[i];	// || label
	}
	a_temp[a_index++] = 0;
	input[temp_index++] = 0;			// || 0x00
	for(int i = 0 ; i < ct_len ; i++)
	{
		a_temp[a_index++] = context[i];
		input[temp_index++] = context[i];//|| context
	}
	a_temp[a_index + 1] = len_to_hex % 256;
	input[temp_index + 1] = len_to_hex % 256;
	len_to_hex /= 256;
	a_temp[a_index + 1] = len_to_hex % 256;
	input[temp_index] = len_to_hex % 256;	// || [L]2

	for(int i = 0 ; i < loop_count ; i++)
	{
		printf("input %d size A data: ", a_size);
		for(int j = 0 ; j < a_size ; j++)
			printf("%02x", a_temp[j]);
		printf("\n");

		fprintf(fp, "Input1 = ");
		for(int k = 0 ; k < a_size ; k++)
			fprintf(fp, "%02x", a_temp[k]);
		fprintf(fp, "\n");

		if(i)
		{
			result = hmac_lsh_digest(algtype, Ki, Ki_len, a_temp, a_size, a_temp);
			if(result != LSH_SUCCESS)
				return result;
		}
		else
		{
			result = hmac_lsh_digest(algtype, Ki, Ki_len, a_temp, a_size, a_temp);
			if(result != LSH_SUCCESS)
				return result;
			a_size = hash_len;
		}

		printf("output A data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", a_temp[j]);
		printf("\n");

		fprintf(fp, "A(%d) = ", i + 1);
		for(int k = 0 ; k < hash_len ; k++)
			fprintf(fp, "%02x", a_temp[k]);
		fprintf(fp, "\n");

		temp_index = 0;
		for(int j = 0 ; j < hash_len ; j++)
			input[temp_index++] = a_temp[j];
		if(byte_r)
		{
			for(temp_index = hash_len ; temp_index < byte_r - 1; temp_index++)
				input[temp_index] = 0;
			input[temp_index] = i + 1;
		}

		printf("input %d size data: ", input_size);
		for(int j = 0 ; j < input_size ; j++)
			printf("%02x", input[j]);
		printf("\n");

		result = hmac_lsh_digest(algtype, Ki, Ki_len, input, input_size, k_temp);
		if(result != LSH_SUCCESS)
			return result;

		printf("output data number %d: ", i + 1);
		for(int j = 0 ; j < hash_len ; j++)
			printf("%02x", k_temp[j]);
		printf("\n");

		fprintf(fp, "Input2 = ");
		for(int k = 0 ; k < input_size ; k++)
			fprintf(fp, "%02x", input[k]);
		fprintf(fp, "\n");
		fprintf(fp, "K(%d) = ", i + 1);
		for(int k = 0 ; k < hash_len ; k++)
			fprintf(fp, "%02x", k_temp[k]);
		fprintf(fp, "\n");

		for(int j = 0 ; j < hash_len ; j++)
		{
			if(result_index == len)
				break;
			output[result_index++] = k_temp[j];
		}
	}

	printf("final output: ");
	for(int i = 0 ; i < len ; i++)
		printf("%02x", output[i]);
	printf("\n");

	free(input);
	free(a_temp);
	free(k_temp);

	return result;
}

lsh_err hmac_kdf_digest(int mode, lsh_type algtype, lsh_u8 *Ki, int Ki_len, lsh_u8 *iv, int iv_len, lsh_u8 *label, int label_len, lsh_u8 *context, int context_len, lsh_uint r, lsh_uint len, lsh_uint hash_len, FILE *fp)
{
	lsh_err result;
	lsh_u8 *k_output;
	double n;

	int byte_r = r / 8;
	int len_byte = len / 8;
	int hash_byte = hash_len / 8;

	n = ceil((double)len_byte / (double) hash_byte);

	k_output = (lsh_u8*) malloc(sizeof(lsh_u8) * len_byte);
	for(int i = 0 ; i < len_byte ; i++)
		k_output[i] = '\0';		// initializing k_output

	fprintf(fp, "n = %d\n\n", (int) n);

	if(mode == CTR_MODE)
	{
		result = hmac_kdf_ctr_digest(algtype, (int) n, byte_r, Ki, Ki_len, label, label_len, context, context_len, len_byte, hash_byte, k_output, fp);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(mode == FB_MODE)
	{
		result = hmac_kdf_fb_digest(algtype, (int) n, byte_r, Ki, Ki_len, label, label_len, context, context_len, len_byte, hash_byte, k_output, fp);
		if(result != LSH_SUCCESS)
			return result;
	}
	else if(mode == DP_MODE)
	{
		result = hmac_kdf_dp_digest(algtype, (int) n, byte_r, Ki, Ki_len, label, label_len, context, context_len, len_byte, hash_byte, k_output, fp);
		if(result != LSH_SUCCESS)
			return result;
	}
	else
		printf("unknown mode \n");

	fprintf(fp, "K0 = ");
	for(int i = 0 ; i < len_byte ; i++)
		fprintf(fp, "%02x", k_output[i]);
	fprintf(fp, "\n");

	free(k_output);

	return result;
}
