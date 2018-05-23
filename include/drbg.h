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

#ifndef _REF_HMAC_H_
#define _REF_HMAC_H_

#include "lsh_def.h"
#include "lsh.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * DRBG 설정 정보
 * drbgtype 난수발생기, 기반암호 알고리즘
 * refreshperiod 상태 갱신주기
 * predicttolerance 예측내성 활성화 여부
 * usingperstring 개별화 문자열 사용 여부
 * usingaddinput 추가 입력 사용 여부
 */
struct DRBG_Administrative {
	lsh_uint drbgtype;
	lsh_uint refreshperiod;
	lsh_uint predicttolerance;
	lsh_uint usingperstring;
	lsh_uint usingaddinput;
};

/**
 * DRBG 계산을 위한 내부 상태 구조체
 */
struct DRBG_LSH_Context {
	union LSH_Context drbg_ctx;
	struct DRBG_Administrative setting;
	lsh_uint working_state;
};


/**
 * DRBG 유도 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] algtype LSH 알고리즘 명세
 * @param [in] data 임의 길이 데이터
 * @param [out] seed 시드
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err drbg_derivation_func(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *data);


/**
 * DRBG 내부 작동 상태 갱신 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] state 작동상태
 * @param [in] seed 시드
 * @param [out] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err drbg_lsh_inner_reseed(struct DRBG_LSH_Context *ctx, const lsh_u8 *state, const lsh_u8 *seed);


/**
 * DRBG 내부 출력 생성 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] state 작동상태
 * @param [out] output 출력
 * @param [out] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err drbg_lsh_inner_output_gen(struct DRBG_LSH_Context *ctx, const lsh_u8 *state);


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
lsh_err drbg_lsh_init(struct DRBG_LSH_Context *ctx, lsh_type algtype, const lsh_u8 *entropy, const lsh_u8 *nonce, const lsh_u8 *per_string);


/**
 * DRBG 갱신 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err drbg_lsh_reseed(struct DRBG_LSH_Context *ctx, const lsh_u8 *entropy, const lsh_u8 *add_input, const lsh_u8 *state);


/**
 * DRBG 출력 생성 함수
 *
 * @param [in] ctx DRBG 내부 상태 구조체
 * @param [in] add_input 추가 입력
 * @param [in] state 작동상태
 *
 * @return LSH_SUCCESS 내부 상태 초기화 성공
 */
lsh_err drbg_lsh_output_gen(struct DRBG_LSH_Context *ctx, const lsh_u8 *add_input, const lsh_u8 *state);


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
lsh_err hmac_lsh_digest(lsh_type algtype, const lsh_u8* key, size_t keybytelen, const lsh_u8* data, size_t databytelen, lsh_u8* digest);

#ifdef __cplusplus
}
#endif

#endif
