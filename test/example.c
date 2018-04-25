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

#pragma warning(disable: 4996)

void lsh_test_type2(lsh_type algtype){
	FILE *input_file, *output_file;
	const lsh_uint MAX_LEN = 1024;

	size_t datalen;
	lsh_u8 data[256 * 4];
	lsh_u8 hash[LSH512_HASH_VAL_MAX_BYTE_LEN];
	lsh_u8 p_lines[10];
	lsh_uint lines;

	lsh_uint i, o, loop_count;
	lsh_uint k;

	int databitlen;

	lsh_err result;
	int bits;

	if (LSH_IS_LSH256(algtype)){
		bits = 256;
	}
	else if (LSH_IS_LSH512(algtype)){
		bits = 512;
	}
	else{
		printf("Unknown LSH Type\n");
		return;
	}

	input_file = fopen("input.txt", "r");
	output_file = fopen("output.txt", "w");
	fgets(data, MAX_LEN, input_file);	// remove first lines
	fgets(data, MAX_LEN, input_file);
	data[strlen(data) - 1] = '\0';

	for(int temp = 10, index = 0; temp < strlen(data); temp++)
		p_lines[index++] = data[temp];
	lines = atoi(p_lines);	//get number of lines

	printf("\n== Test Vector for LSH-%d-%d ==\n", bits, LSH_GET_HASHBIT(algtype));
	printf("number of test vector: %d \n", lines);
	fprintf(output_file, "Algo_ID = LSH-%d_%d", bits, LSH_GET_HASHBIT(algtype));	//output text
	for(loop_count = 0 ; loop_count < lines ; loop_count++)
	{
		fgets(data, MAX_LEN, input_file);
		data[strlen(data) - 1] = '\0';
		// remove LF character created by fgets function

		for(i = 0, o = 0 ; i < strlen(data) ; i++)
		{	// remove " character
			if(data[i] != '\"')
			{
				data[o] = data[i];
				o++;
			}
		}
		data[o] = '\0';	// add NULL character at the end of String
		datalen = strlen(data);
		databitlen = datalen * 8;

		printf("\n> Input Message Length in Bits: %d\n", databitlen);
		printf("- Input Message:\n");

		for (k = 0; k < datalen; k++) {
			if (k != 0 && k % 32 == 0){
				printf("\n");
			}

			printf("%02x", data[k]);
			if (k % 4 == 3){
				printf(" ");
			}
		}

		printf("\n");

		for (k = 0; k < datalen; k++) {
			if (k != 0 && k % 71 == 0){
				printf("\n");
			}
			printf("%c", data[k]);
		}

		printf("\n\n");

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

			if(!(k % 14))	//output text
				fprintf(output_file, "\n");
			fprintf(output_file, "%02x", hash[k]);

			if (k % 4 == 3){
				printf(" ");
			}

		}
		printf("\n\n");
		fprintf(output_file, "\n");
	}

	printf("== Test Vector from input.txt ==\n");
	printf("== Test Result saved at output.txt ==\n");
	printf("== Test End==\n");
	fclose(input_file);
	fclose(output_file);
	return;
}

int main(){
	FILE *input_file;
	const lsh_uint MAX_LEN = 1024;
	char *algtype = NULL;
	char str_alg[MAX_LEN];

	input_file = fopen("input.txt", "r");

	if(input_file != NULL)
	{
		fgets(str_alg, MAX_LEN, input_file);

		if(strstr(str_alg, "LSH") != NULL)
		{
			algtype = strstr(str_alg, "LSH");		// get LSH algorithm type
			algtype[strlen(algtype) - 1] = '\0';
		}
	}
	else
	{
		printf("couldn't file open");
		return 0;
	}

	fclose(input_file);

	// call lsh function
	if(algtype != NULL) {
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
		else
		{
			printf("unknown algtype: %s \n", algtype);
			return 0;
		}
	}
	else
	{
		printf("algtype setting failed \n");
		return 0;
	}

	return 0;
}
