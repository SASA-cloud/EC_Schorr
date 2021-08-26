#pragma once
#ifndef EC_SCHNORR_H
#define EC_SCHNORR_H

#include<string.h>
#include<openssl/evp.h>
#include<stdio.h>
#include<fstream>
#include<string>
#include<openssl/ec.h>
#include<openssl/ecdsa.h>
#include<openssl/bn.h>
#include<openssl/sha.h>
#include<openssl/bio.h>
#include<openssl/crypto.h>


// ǩ����ʽ
struct schnorr_sig {
	unsigned char R_x[32];
	int R_y; // 1����0ż�� ��ʾ��R��������
	unsigned char s[32];
};


// �ȽϺ���
int cmpfunc(const void* a, const void* b);


// ȡ��������ʱ�����λ��
int mid_value(int* array, int len);



/** ���ļ�����hash�ĺ���
*  \param  fileName    �ļ�����
*  \param  algoName    hash�㷨����
*  \param  hv		   �������hashֵ
*/
int digest(const char* fileName, const char* algoName, unsigned char* hv);


/** ec schnorrǩ�� ��Կ���� ��Բ����Ϊscep256k1
*  \param  sig_key    �����������Կ
*/
int ec_shnorr_key_gen(EC_KEY** sig_key);


/** nonce������ �ú�������һ�������k ȡֵ��Χ��[1,n)֮�� nΪbase point����
 *  \param	nonce	   �������������ɵ���
 *  \param	range	   �������Ĵ�С��[1,range)֮��
 *  \return 1 on success and 0 fail
 */
int nonce_generation(BIGNUM* nonce32, const BIGNUM* range);


/** challenge������ = hash(R, pk, msg32)
 *  \param	e		   ���������challenge
 *  \param	group	   Ⱥ
 *  \param  R		   commitment
 *  \param  pk         ��Կ
 *  \param  msg32      32bytes�Ĵ�ǩ����Ϣ��һ���ʾһ����Ϣ��hashֵ
 *  \return 1 on success and 0 fail
 */
int schnorr_challenge(BIGNUM* e, const EC_GROUP* group, const EC_POINT* R, const EC_POINT* pk, const unsigned char* msg32);


/** ec schnorrǩ�� ǩ���㷨
 *  \param	sig64		   ǩ��(�����ǩ��)
 *  \param	msg32		   32bytes�Ĵ�ǩ����Ϣ��һ���ʾһ����Ϣ��hashֵ
 *  \param  sig_key        ǩ������Կ,���ݰ�����Կ˽Կ��
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_sign(schnorr_sig* sig, const unsigned char* msg32, EC_KEY* sig_key);


/** ec schnorrǩ�� ������֤
 *  \param	sig64		   ǩ��
 *  \param	msg32		   ԭ��Ϣ
 *  \param  eckey          ��Կ����Կ����ֻ���˹�Կ��
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_verify(const schnorr_sig* sig, const unsigned char* msg32, EC_KEY* eckey);



/**  ec schnorrǩ�� ����֤
 *  \param	n			   ��֤����Ŀ
 *  \param	eckey_array    ��Կ����
 *  \param  msg32_array    ��Ϣ����
 *  \param  sig64_array    ǩ������
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_batch_verify(int n, EC_KEY* eckey_array[], unsigned char* msg32_array[], schnorr_sig* sig_array[]);


#endif // !EC_SCHNORR_H
