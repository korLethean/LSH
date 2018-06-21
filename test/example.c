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

#include <stdio.h>
#include <string.h>
#include "../include/lsh.h"
#include "../include/hmac.h"
#include "../include/drbg.h"
#include "../include/hmac_drbg.h"

#define MAX_FILE_NAME_LEN 256
#define MAX_READ_LEN 3072
#define MAX_DATA_LEN 1000001	// original 256 * 4

#pragma warning(disable: 4996)

void lsh_test_drive() {
	FILE *input_file;
	char file_name[MAX_FILE_NAME_LEN];
	lsh_uint bits[2] = {256, 512};
	lsh_uint hashbits[4] = {224, 256, 384, 512};
	char *algtype = NULL;
	char str_alg[MAX_READ_LEN];

	for(int b = 0 ; b < 2 ; b++)
	{
		for(int h = 0 ; h < 4 ; h++)
		{
			if(b < 1 && h > 1)
				break;
			sprintf(file_name, "Hash_test/LSH-%d_%d.txt", bits[b], hashbits[h]);
			input_file = fopen(file_name, "r");

			if(input_file != NULL)
			{
				fgets(str_alg, MAX_READ_LEN, input_file);
				algtype = strstr(str_alg, "LSH");		// get LSH algorithm type
			}
			else
			{
				printf("file does not exist");
				return ;
			}

			fclose(input_file);

			// call lsh function
			if(algtype != NULL)
			{
				algtype[strlen(algtype) - 1] = '\0';	// remove LF character
				if(!strcmp(algtype, "LSH-256_224"))
					lsh_test_type2(LSH_TYPE_256_224);
				else if(!strcmp(algtype, "LSH-256_256"))
					lsh_test_type2(LSH_TYPE_256_256);
				else if(!strcmp(algtype, "LSH-512_224"))
					lsh_test_type2(LSH_TYPE_512_224);
				else if(!strcmp(algtype, "LSH-512_256"))
					lsh_test_type2(LSH_TYPE_512_256);
				else if(!strcmp(algtype, "LSH-512_384"))
					lsh_test_type2(LSH_TYPE_512_384);
				else if(!strcmp(algtype, "LSH-512_512"))
					lsh_test_type2(LSH_TYPE_512_512);
				else	// LSH type typo
					printf("unknown LSH type: %s \n", algtype);
			}
			else		// excluding other algorithm or typo
				printf("algorithm type reading failed \n");
		}
	}
}

void lsh_test_type2(lsh_type algtype){
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];

	size_t datalen;
	lsh_u8 data[MAX_DATA_LEN];
	lsh_u8 hash[LSH512_HASH_VAL_MAX_BYTE_LEN];
	lsh_u8 p_lines[10];
	lsh_uint lines;

	lsh_uint i, o, loop_count;
	lsh_uint k;

	int databitlen;

	lsh_err result;
	int bits;

	if (LSH_IS_LSH256(algtype))
		bits = 256;
	else if (LSH_IS_LSH512(algtype))
		bits = 512;
	else{
		printf("Unknown LSH Type\n");
		return;
	}

	sprintf(input_file_name, "Hash_test/LSH-%d_%d.txt", bits, LSH_GET_HASHBIT(algtype));
	sprintf(output_file_name, "Hash_test/LSH-%d_%d_rsp.txt", bits, LSH_GET_HASHBIT(algtype));
	input_file = fopen(input_file_name, "r");
	output_file = fopen(output_file_name, "w");
	fgets(data, MAX_READ_LEN, input_file);	// remove first line
	fgets(data, MAX_READ_LEN, input_file);
	data[strlen(data) - 1] = '\0';		// remove LF character

	for(int temp = 10, index = 0; temp < strlen(data); temp++)
		p_lines[index++] = data[temp];
	lines = atoi(p_lines);	//get number of lines

	printf("\n== Test Vector for LSH-%d-%d ==\n", bits, LSH_GET_HASHBIT(algtype));
	printf("number of test vector: %d \n", lines);
	fprintf(output_file, "Algo_ID = LSH-%d_%d \n", bits, LSH_GET_HASHBIT(algtype));	//output text
	for(loop_count = 0 ; loop_count < lines ; loop_count++)
	{
		fgets(data, MAX_READ_LEN, input_file);
		data[strlen(data) - 1] = '\0';
		// remove LF character created by fgets function

		for(i = 0, o = 0 ; i < strlen(data) ; i++)
		{	// remove " character
			if(data[i] != '\"')
				data[o++] = data[i];
		}
		data[o] = '\0';	// add NULL character at the end of String
		datalen = strlen(data);
		databitlen = datalen * 8;

		if(datalen == 1 && data[0] == 'a') // use only "a" million
		{
			for(int temp = 0 ; temp < MAX_DATA_LEN ; temp++)
				data[temp] = 'a';
			data[MAX_DATA_LEN - 1] = '\0';
			datalen = strlen(data);
			databitlen = datalen * 8;
		}
/****************** console output ******************
		printf("\n> Input Message Length in Bits: %d\n", databitlen);
		printf("- Input Message:\n");

		for (k = 0; k < datalen; k++) {
			if (k != 0 && k % 71 == 0)
				printf("\n");
			printf("%c", data[k]);
		}

		printf("\n");

		for (k = 0; k < datalen; k++) {
			if (k != 0 && k % 32 == 0){
				printf("\n");
			}

			printf("%02x", data[k]);
			if (k % 4 == 3){
				printf(" ");
			}
		}

		printf("\n\n");*/

		result = lsh_digest(algtype, data, databitlen, hash);
		if (result != LSH_SUCCESS){
			printf("ERROR - 0x%04x\n", result);
			return;
		}
		printf("- Hash Value:\n");
		for (k = 0; k < LSH_GET_HASHBYTE(algtype); k++){
			if (k != 0 && k % 32 == 0){
				printf("\n");
			}

			printf("%02x", hash[k]);
			fprintf(output_file, "%02x", hash[k]);

			if (k % 4 == 3){
				printf(" ");
			}
		}
		printf("\n\n");
		fprintf(output_file, "\n");
	}

	printf("== Test Vector from %s ==\n", input_file_name);
	printf("== Test Result saved at %s ==\n", output_file_name);
	printf("== Test End==\n");
	fclose(input_file);
	fclose(output_file);
	return;
}

void hmac_lsh_reference(FILE *input_file, FILE *output_file, char *input_file_name, char *output_file_name, char *algid, const lsh_uint *bits, const lsh_uint *hashbits) {
	lsh_u8 p_keynum[10], p_msgnum[10];
	lsh_uint keynum, msgnum;
	lsh_uint keylen, msglen, key_vlen;
	lsh_type t_type;
	int i, o;

	lsh_u8 g_hmac_key_data[10][2048];
	lsh_u8 g_hmac_key_value[1024];
	lsh_u8 g_lsh_test_data[MAX_DATA_LEN];

	lsh_u8 hmac_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	for(int b = 0 ; b < 2 ; b++)
	{
		for(int h = 0 ; h < 4 ; h++)
		{
			if(b < 1 && h > 1)
				break;

			t_type = LSH_MAKE_TYPE(b, hashbits[h]); // b == 0 -> 256 | b == 1 -> 512

			sprintf(input_file_name, "HMAC_test/reference/HMAC_LSH-%d_%d.txt", bits[b], hashbits[h]);
			sprintf(output_file_name, "HMAC_test/reference/HMAC_LSH-%d_%d_rsp.txt", bits[b], hashbits[h]);
			sprintf(algid, "HMAC_LSH-%d_%d", bits[b], hashbits[h]);
			input_file = fopen(input_file_name, "r");
			output_file = fopen(output_file_name, "w");

			if(input_file == NULL)
			{
				printf("file does not exist \n");
				continue ;
			}
			else
				fprintf(output_file, "Algo_ID = %s\n\n", algid);

			fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// remove first line
			fgets(g_lsh_test_data, MAX_READ_LEN, input_file);
			g_lsh_test_data[strlen(g_lsh_test_data) - 1] = '\0';	// remove LF character

			for(int temp = 10, index = 0; temp < strlen(g_lsh_test_data); temp++)
				p_keynum[index++] = g_lsh_test_data[temp];
			keynum = atoi(p_keynum);	//get number of keys

			for(int temp = 0 ; temp < keynum ; temp++)
			{	// get key value
				fgets(g_hmac_key_data[temp], MAX_READ_LEN, input_file);
				g_hmac_key_data[temp][strlen(g_hmac_key_data[temp]) - 1] = '\0'; // remove LF character
			}

			fgets(g_lsh_test_data, MAX_READ_LEN, input_file);
			g_lsh_test_data[strlen(g_lsh_test_data) - 1] = '\0';

			for(int temp = 10, index = 0; temp < strlen(g_lsh_test_data); temp++)
				p_msgnum[index++] = g_lsh_test_data[temp];
			msgnum = atoi(p_msgnum);	//get number of messages

			for(int key_index = 0 ; key_index < keynum ; key_index++)
			{
				keylen = strlen(g_hmac_key_data[key_index]);

				for(int r = 0, w = 0 ; r < keylen ; r += 2)
				{
					lsh_u8 temp_arr[3] = {g_hmac_key_data[key_index][r], g_hmac_key_data[key_index][r+1], '\0'};
					g_hmac_key_value[w++] = strtol(temp_arr, NULL, 16);
				}		// key string to hex
				key_vlen = keylen / 2;

				fprintf(output_file, "Key = ");
				for(int kvindex = 0 ; kvindex < key_vlen ; kvindex++)
					fprintf(output_file, "%02x", g_hmac_key_value[kvindex]);
				fprintf(output_file, "\n");

				rewind(input_file);
				for(int skip = 0 ; skip < keynum + 3 ; skip++)
					fgets(g_lsh_test_data, MAX_READ_LEN, input_file); //skip lines

				for(int msg_index = 0 ; msg_index < msgnum ; msg_index++)
				{
					fgets(g_lsh_test_data, MAX_READ_LEN, input_file);
					g_lsh_test_data[strlen(g_lsh_test_data) - 1] = '\0';

					for(i = 0, o = 0 ; i < strlen(g_lsh_test_data) ; i++)
					{	// remove " character
						if(g_lsh_test_data[i] != '\"')
							g_lsh_test_data[o++] = g_lsh_test_data[i];
					}
					g_lsh_test_data[o] = '\0';	// add NULL character at the end of String

					msglen = strlen(g_lsh_test_data);

					if(msglen == 1 && g_lsh_test_data[0] == 'a') // use only "a" million
					{
						for(int data_index = 0 ; data_index < MAX_DATA_LEN ; data_index++)
							g_lsh_test_data[data_index] = 'a';
						g_lsh_test_data[MAX_DATA_LEN - 1] = '\0';
						msglen = strlen(g_lsh_test_data);
					}

					hmac_lsh_digest(t_type, g_hmac_key_value, key_vlen, g_lsh_test_data, msglen, hmac_result);

					for (int hash_index = 0; hash_index < LSH_GET_HASHBYTE(t_type); hash_index++){
						fprintf(output_file, "%02x", (lsh_u8)hmac_result[hash_index]);
					}
					fprintf(output_file, "\n");
				}
				fprintf(output_file, "\n");
			}
			printf("%s file opened \n", input_file_name);
		}
	}
	fclose(input_file);
	fclose(output_file);
}

void hmac_lsh_testvector(FILE *input_file, FILE *output_file, char *input_file_name, char *output_file_name, char *algid, const lsh_uint *bits, const lsh_uint *hashbits) {
	lsh_u8 p_taglen[10];
	lsh_uint keylen, taglen, msglen;
	lsh_uint key_vlen, msg_vlen;
	lsh_type t_type;

	lsh_u8 g_hmac_key_data[2048];
	lsh_u8 g_hmac_key_value[1024];
	lsh_u8 g_lsh_test_data[MAX_DATA_LEN];
	lsh_u8 g_lsh_test_value[MAX_DATA_LEN / 2];

	lsh_u8 hmac_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	int count;
	int key_index, msg_index, value_index;

	for(int b = 0 ; b < 2 ; b++)
	{
		for(int h = 0 ; h < 4 ; h++)
		{
			if(b < 1 && h > 1)
				break;

			t_type = LSH_MAKE_TYPE(b, hashbits[h]); // b == 0 -> 256 | b == 1 -> 512
			count = 0;

			sprintf(input_file_name, "HMAC_test/testvector/HMAC_LSH-%d_%d.txt", bits[b], hashbits[h]);
			sprintf(output_file_name, "HMAC_test/testvector/HMAC_LSH-%d_%d_rsp.txt", bits[b], hashbits[h]);
			sprintf(algid, "HMAC_LSH-%d_%d", bits[b], hashbits[h]);
			input_file = fopen(input_file_name, "r");
			output_file = fopen(output_file_name, "w");
			if(input_file == NULL)
			{
				printf("file does not exist \n");
				return ;
			}
			else
				fprintf(output_file, "Algo_ID = %s\n\n", algid);

			fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// skip two lines
			fgets(g_lsh_test_data, MAX_READ_LEN, input_file);

			while(!feof(input_file))
			{
				fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// skip count line
				fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// skip key length line

				fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// read tag length line
				g_lsh_test_data[strlen(g_lsh_test_data) - 1] = '\0';
				for(int temp = 7, index = 0; temp < strlen(g_lsh_test_data); temp++)
					p_taglen[index++] = g_lsh_test_data[temp];
				taglen = atoi(p_taglen);	//get tag length

				fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// read key line

				for(key_index = 6, value_index = 0; key_index < strlen(g_lsh_test_data)-1; key_index++)
					g_hmac_key_data[value_index++] = g_lsh_test_data[key_index];
				g_hmac_key_data[value_index] = '\0';
				keylen = strlen(g_hmac_key_data);	// calculate key length
				for(int r = 0, w = 0 ; r < keylen ; r += 2)
				{
					lsh_u8 temp_arr[3] = {g_hmac_key_data[r], g_hmac_key_data[r+1], '\0'};
					g_hmac_key_value[w++] = strtol(temp_arr, NULL, 16);
				}		// key string to hex
				key_vlen = keylen / 2;

				fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// read msg line

				for(msg_index = 6, value_index = 0; msg_index < strlen(g_lsh_test_data)-1; msg_index++)
					g_lsh_test_data[value_index++] = g_lsh_test_data[msg_index];
				g_lsh_test_data[value_index] = '\0';
				msglen = strlen(g_lsh_test_data);	// calculate msg length

				for(int r = 0, w = 0 ; r < msglen ; r += 2)
				{
					lsh_u8 temp_arr[3] = {g_lsh_test_data[r], g_lsh_test_data[r+1], '\0'};
					g_lsh_test_value[w++] = strtol(temp_arr, NULL, 16);
				}
				msg_vlen = msglen / 2;

				hmac_lsh_digest(t_type, g_hmac_key_value, key_vlen, g_lsh_test_value, msg_vlen, hmac_result);

				fprintf(output_file,"COUNT = %d\n", count++);
				fprintf(output_file,"Klen = %d\n", key_vlen);
				fprintf(output_file,"Tlen = %d\n", taglen);
				fprintf(output_file,"Key = ");
				for(int kvindex = 0 ; kvindex < key_vlen ; kvindex++)
					fprintf(output_file,"%02x", g_hmac_key_value[kvindex]);
				fprintf(output_file, "\n");
				fprintf(output_file,"Msg = ");
				for(int mvindex = 0 ; mvindex < msg_vlen ; mvindex++)
					fprintf(output_file,"%02x", g_lsh_test_value[mvindex]);
				fprintf(output_file, "\n");
				fprintf(output_file,"Mac = ");
				for (int hash_index = 0; hash_index < taglen; hash_index++){
					fprintf(output_file, "%02x", (lsh_u8)hmac_result[hash_index]);
				}
				fprintf(output_file,"\n\n");

				fgets(g_lsh_test_data, MAX_READ_LEN, input_file);	// skip blank line
			}
			printf("%s file opened \n", input_file_name);

			fclose(input_file);
			fclose(output_file);
		}
	}
}

int hmac_lsh_test_type2(){
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	char algid[MAX_FILE_NAME_LEN];
	const lsh_uint bits[2] = {256, 512};
	const lsh_uint hashbits[4] = {224, 256, 384, 512};

	hmac_lsh_reference(input_file, output_file, input_file_name, output_file_name, algid, bits, hashbits);
	hmac_lsh_testvector(input_file, output_file, input_file_name, output_file_name, algid, bits, hashbits);

	return 0;
}


void drbg_lsh_test_drive()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_u8 drbg_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	lsh_type algtype;
	lsh_u8 entropy[3][64];
	lsh_u8 nonce[32];
	lsh_u8 per_string[64];
	lsh_u8 add_input[2][64];
	lsh_uint output_bits = 512;
	lsh_uint reseed_cycle = 1;

	int entropy_size	= 32;
	int nonce_size		= 16;
	int per_size		= 32;
	int add_size		= 32;

	sprintf(input_file_name, "DRBG_test/reference/Hash_DRBG_LSH-256-256(no PR).txt");
	input_file = fopen(input_file_name, "r");

	sprintf(output_file_name, "DRBG_test/reference/Hash_DRBG_LSH-256-256(no PR)_rsp.txt");
	output_file = fopen(output_file_name, "w");

	algtype = LSH_TYPE_256_256;

	if(input_file != NULL)
	{
		fgets(read_line, MAX_READ_LEN, input_file);	// remove first line
		fgets(read_line, MAX_READ_LEN, input_file);	// remove second line
		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy1
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy2
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy3
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[2][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read nonce
		for(int r = 8, w = 0 ; r < nonce_size * 2 + 8; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			nonce[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read perstring
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			per_string[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput1
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput2
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256 \n\n");	//output text
		fprintf(output_file, "entropy = ");
		for(int i = 0 ; i < entropy_size ; i++)
			fprintf(output_file, "%02x", entropy[0][i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "nonce = ");
		for(int i = 0 ; i < nonce_size ; i++)
			fprintf(output_file, "%02x", nonce[i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "perString = ");
		for(int i = 0 ; i < per_size ; i++)
			fprintf(output_file, "%02x", per_string[i]);
		fprintf(output_file, "\n\n");


		drbg_lsh_digest(algtype, entropy, entropy_size, nonce, nonce_size, per_string, per_size, add_input, add_size, output_bits, reseed_cycle, drbg_result, output_file);
	}
	else
	{
		printf("file does not exist");
		return ;
	}

	printf("DRBG Finished \n");

	fclose(input_file);
	fclose(output_file);
}

void hmac_drbg_lsh_test_drive()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_u8 hmac_drbg_result[128];

	lsh_type algtype;
	lsh_u8 entropy[3][64];
	lsh_u8 nonce[32];
	lsh_u8 per_string[64];
	lsh_u8 add_input[2][64];
	lsh_uint output_bits = 512;
	lsh_uint reseed_cycle = 1;

	int entropy_size	= 32;
	int nonce_size		= 16;
	int per_size		= 32;
	int add_size		= 32;

	sprintf(input_file_name, "HMAC_DRBG_test/reference/HMAC_DRBG_LSH-256-256(no PR).txt");
	input_file = fopen(input_file_name, "r");

	sprintf(output_file_name, "HMAC_DRBG_test/reference/HMAC_DRBG_LSH-256-256(no PR)_rsp.txt");
	output_file = fopen(output_file_name, "w");
	fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-256_256 \n\n");

	printf("test data from: %s \n", input_file_name);

	algtype = LSH_TYPE_256_256;

	if(input_file != NULL)
	{
		fgets(read_line, MAX_READ_LEN, input_file);	// remove first line
		fgets(read_line, MAX_READ_LEN, input_file);	// remove second line
		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy1
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy2
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy3
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[2][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read nonce
		for(int r = 8, w = 0 ; r < nonce_size * 2 + 8; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			nonce[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read perstring
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			per_string[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput1
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput2
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		//output text
		fprintf(output_file, "entropy = ");
		for(int i = 0 ; i < entropy_size ; i++)
			fprintf(output_file, "%02x", entropy[0][i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "nonce = ");
		for(int i = 0 ; i < nonce_size ; i++)
			fprintf(output_file, "%02x", nonce[i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "perString = ");
		for(int i = 0 ; i < per_size ; i++)
			fprintf(output_file, "%02x", per_string[i]);
		fprintf(output_file, "\n\n");


		hmac_drbg_lsh_digest(algtype, entropy, entropy_size, nonce, nonce_size, per_string, per_size, add_input, add_size, output_bits, reseed_cycle, hmac_drbg_result, output_file);
	}
	else
	{
		printf("file does not exist");
		return ;
	}

	printf("HMAC DRBG Finished \n");

	fclose(input_file);
	fclose(output_file);
}

void drbg_lsh_testvector_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_pr1[256];
	lsh_u8 entropy_pr2[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}
		sprintf(input_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
				printf("Prediction Resistance: True \n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
				printf("Prediction Resistance: false \n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr1[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}


				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr2[w++] = strtol(str_to_hex, NULL, 16);
				}
				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				drbg_lsh_testvector_pr_digest(algtype, prediction_resistance, entropy, entropy_pr1, entropy_pr2, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInput1 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr1[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nEntropyInput2 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("DRBG test finished \n");
}

void drbg_lsh_testvector_no_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_re[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input_re[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}
		sprintf(input_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(no PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(no PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
				printf("Prediction Resistance: True \n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
				printf("Prediction Resistance: false \n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 21, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_re[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input_re[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				drbg_lsh_testvector_no_pr_digest(algtype, prediction_resistance, entropy, entropy_re, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input_re, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInputReseed = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_re[i]);
				fprintf(output_file, "\nAdditionalInputReseed = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input_re[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("DRBG testvector finished \n");
}

void hmac_drbg_lsh_testvector_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_pr1[256];
	lsh_u8 entropy_pr2[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}
		sprintf(input_file_name, "HMAC_DRBG_test/testvector/HMAC_DRBG(LSH-%d_%d(-)(PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "HMAC_DRBG_test/testvector/HMAC_DRBG(LSH-%d_%d(-)(PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
				//printf("Prediction Resistance: True \n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
				//printf("Prediction Resistance: false \n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr1[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}


				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr2[w++] = strtol(str_to_hex, NULL, 16);
				}
				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				hmac_drbg_lsh_tv_pr_digest(algtype, prediction_resistance, entropy, entropy_pr1, entropy_pr2, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInput1 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr1[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nEntropyInput2 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("HMAC DRBG testvector finished \n");
}

int main()
{
	//lsh_test_drive();
	//hmac_lsh_test_type2();
	//drbg_lsh_test_drive();
	//hmac_drbg_lsh_test_drive();
	//drbg_lsh_testvector_pr();
	//drbg_lsh_testvector_no_pr();
	hmac_drbg_lsh_testvector_pr();

	return 0;
}
