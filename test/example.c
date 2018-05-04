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
	lsh_uint keylen, msglen;
	lsh_type t_type;
	int i, o;

	lsh_u8 g_hmac_key_data[10][2048];
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
				return ;
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
				fprintf(output_file,"Key = %s\n", g_hmac_key_data[key_index]);

				rewind(input_file);
				for(int skip = 0 ; skip < keynum + 3 ; skip++)
					fgets(g_lsh_test_data, MAX_READ_LEN, input_file); //skip lines

				for(int temp = 0 ; temp < msgnum ; temp++)
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

					hmac_lsh_digest(t_type, g_hmac_key_data[key_index], keylen, g_lsh_test_data, msglen, hmac_result);

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
	lsh_uint keylen, taglen, msglen11;
	lsh_type t_type;

	lsh_u8 g_hmac_key_data[10][2048];
	lsh_u8 g_lsh_test_data[MAX_DATA_LEN];

	lsh_u8 hmac_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	for(int b = 0 ; b < 2 ; b++)
	{
		for(int h = 0 ; h < 4 ; h++)
		{
			if(b < 1 && h > 1)
				break;

			t_type = LSH_MAKE_TYPE(b, hashbits[h]); // b == 0 -> 256 | b == 1 -> 512

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

int main()
{
	//lsh_test_drive();
	hmac_lsh_test_type2();

	return 0;
}
