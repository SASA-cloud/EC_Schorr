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


// 签名格式
struct schnorr_sig {
	unsigned char R_x[32];
	int R_y; // 1奇数0偶数 表示点R的纵坐标
	unsigned char s[32];
};


// 比较函数
int cmpfunc(const void* a, const void* b);


// 取测试运行时间的中位数
int mid_value(int* array, int len);



/** 对文件进行hash的函数
*  \param  fileName    文件名称
*  \param  algoName    hash算法名称
*  \param  hv		   储存输出hash值
*/
int digest(const char* fileName, const char* algoName, unsigned char* hv);


/** ec schnorr签名 密钥生成 椭圆曲线为scep256k1
*  \param  sig_key    储存输出的密钥
*/
int ec_shnorr_key_gen(EC_KEY** sig_key);


/** nonce的生成 该函数生成一个随机的k 取值范围在[1,n)之间 n为base point的秩
 *  \param	nonce	   储存输出随机生成的数
 *  \param	range	   生成数的大小在[1,range)之间
 *  \return 1 on success and 0 fail
 */
int nonce_generation(BIGNUM* nonce32, const BIGNUM* range);


/** challenge的生成 = hash(R, pk, msg32)
 *  \param	e		   储存输出的challenge
 *  \param	group	   群
 *  \param  R		   commitment
 *  \param  pk         公钥
 *  \param  msg32      32bytes的待签名消息，一般表示一个消息的hash值
 *  \return 1 on success and 0 fail
 */
int schnorr_challenge(BIGNUM* e, const EC_GROUP* group, const EC_POINT* R, const EC_POINT* pk, const unsigned char* msg32);


/** ec schnorr签名 签名算法
 *  \param	sig64		   签名(输出的签名)
 *  \param	msg32		   32bytes的待签名消息，一般表示一个消息的hash值
 *  \param  sig_key        签名的密钥,内容包括公钥私钥等
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_sign(schnorr_sig* sig, const unsigned char* msg32, EC_KEY* sig_key);


/** ec schnorr签名 单独验证
 *  \param	sig64		   签名
 *  \param	msg32		   原消息
 *  \param  eckey          密钥（密钥对中只存了公钥）
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_verify(const schnorr_sig* sig, const unsigned char* msg32, EC_KEY* eckey);



/**  ec schnorr签名 批验证
 *  \param	n			   验证的数目
 *  \param	eckey_array    公钥数组
 *  \param  msg32_array    消息数组
 *  \param  sig64_array    签名数组
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_batch_verify(int n, EC_KEY* eckey_array[], unsigned char* msg32_array[], schnorr_sig* sig_array[]);


#endif // !EC_SCHNORR_H
