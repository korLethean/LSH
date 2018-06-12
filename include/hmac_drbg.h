#ifndef INCLUDE_HMAC_DRBG_H_
#define INCLUDE_HMAC_DRBG_H_

#include "drbg.h"

struct HMAC_DRBG_LSH_Context {
	union LSH_Context drbg_ctx;
	struct DRBG_Administrative setting;
	lsh_u8 working_state_key[STATE_MAX_SIZE_512] = {0x00, };
	lsh_u8 working_state_V[STATE_MAX_SIZE_512] = {0x01, };
	int reseed_counter;
};

lsh_err hmac_drbg_update(struct DRBG_LSH_Context *ctx, const lsh_u8 *data, int data_size, lsh_u8 *output);


/**
 * DRBG 초기화 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] entropy 엔트로피
 * @param [in] nonce 논스
 * @param [in] per_string 개별화 문자열
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_drbg_lsh_init(struct DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf);


/**
 * DRBG 출력 생성 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hamc_drbg_lsh_gen(struct DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf);


/**
 * init, update, final 과정을 한번에 수행하여 HMAC을 계산한다.
 *
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] key 키
 * @param [in] keybytelen 키 길이 (바이트 단위)
 * @param [in] data 데이터
 * @param [in] databytelen 데이터 길이 (바이트 단위)
 * @param [out] digest HMAC 출력 버퍼
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_drbg_lsh_digest(lsh_type algtype, lsh_u8 (*entropy)[64], int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 (*add_input)[64], int add_size, int output_bits, int cycle, lsh_u8 *drbg, FILE *outf);


#endif /* INCLUDE_HMAC_DRBG_H_ */
