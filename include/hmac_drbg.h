#ifndef INCLUDE_HMAC_DRBG_H_
#define INCLUDE_HMAC_DRBG_H_

#include <stdio.h>
#include <stdbool.h>
#include "lsh_def.h"
#include "lsh.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STATE_MAX_SIZE 128

/**
 * DRBG 설정 정보
 * drbgtype 난수발생기, 기반암호 알고리즘
 * refresh_period 상태 갱신주기
 * prediction_resistance 예측내성 활성화 여부
 * using_perstring 개별화 문자열 사용 여부
 * using_addinput 추가 입력 사용 여부
 */
struct HMAC_DRBG_Administrative {
	lsh_type drbgtype;
	lsh_uint refresh_period;
	bool prediction_resistance;
	bool using_perstring;
	bool using_addinput;
	bool is_addinput_null;
};


/**
 * HMAC DRBG 계산을 위한 내부 상태 구조체
 */
struct HMAC_DRBG_LSH_Context {
	union LSH_Context drbg_ctx;
	struct HMAC_DRBG_Administrative setting;
	lsh_u8 working_state_V[STATE_MAX_SIZE];
	lsh_u8 working_state_Key[STATE_MAX_SIZE];
	int reseed_counter;
	int output_bits;
};


/**
 * HMAC DRBG 갱신 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] data 임의 길이 데이터
 * @param [out] seed 시드
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_drbg_lsh_update(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *data, int data_size, FILE *outf, bool tv);


/**
 * HMAC DRBG 초기화 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] entropy 엔트로피
 * @param [in] nonce 논스
 * @param [in] per_string 개별화 문자열
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_drbg_lsh_init(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *nonce, int non_size, const lsh_u8 *per_string, int per_size, FILE *outf, bool tv);


/**
 * HMAC DRBG 갱신 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_drbg_lsh_reseed(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, FILE *outf, bool tv);


/**
 * HMAC DRBG 출력 생성 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err hmac_drbg_lsh_output_gen(struct HMAC_DRBG_LSH_Context *ctx, const lsh_u8 *entropy, int ent_size, const lsh_u8 *add_input, int add_size, int cycle, lsh_u8 *drbg, int *counter, FILE *outf, bool tv);


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

lsh_err hmac_drbg_tv_lsh_digest(lsh_type algtype, bool pr, lsh_u8 *ent1, lsh_u8 *ent2, lsh_u8 *ent3, int ent_size, lsh_u8 *nonce, int non_size, lsh_u8 *per_string, int per_size, lsh_u8 *add1, lsh_u8 *add2, int add_size, int output_bits, int cycle, lsh_u8 *drbg);


#endif /* INCLUDE_HMAC_DRBG_H_ */
