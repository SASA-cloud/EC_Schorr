
#ifndef EC_SCHNORR_C
#define EC_SCHNORR_C

#include"ec_schorr.h"
#include<time.h>
#include<stdlib.h>


#pragma warning(disable : 4996)
#define MAXN 100
#ifdef  __cplusplus
extern "C" {
#include<openssl\applink.c>
}
#endif

using namespace std;

const int test_times = 10000; // 测试次数

// 比较函数
int cmpfunc(const void* a, const void* b) {
	return(*(clock_t*)a - *(clock_t*)b);
}

// 取测试运行时间的中位数
int mid_value(clock_t* array, int len) {
	qsort((void*)array, (size_t)len, sizeof(clock_t), cmpfunc);
	if (len % 2) { // odd
		return array[len / 2];
	}
	else {
		return (array[len / 2 - 1] + array[len / 2]) / 2;
	}
}

/** 对文件进行hash的函数
*  \param  fileName    文件名称
*  \param  algoName    hash算法名称
*  \param  hv		   储存输出hash值
*/
int digest(const char* fileName, const char* algoName, unsigned char* hv) {

	const EVP_MD* algo = NULL;
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // contex
	unsigned char hashValue[EVP_MAX_MD_SIZE]; // hash值
	memset(hashValue, 0, EVP_MAX_MD_SIZE);
	unsigned int hashLength; //hash值长度
	string message;


	//文件内容读取
	ifstream ifile; // 读入文件进ifile对象里
	ifile.open(fileName, std::fstream::binary);//二进制形式读取
	char c;
	while (ifile.get(c))
		message += c; // 把文件内容储存到message中

	// 从算法名字取得算法
	algo = EVP_get_digestbyname(algoName);
	if (algo == NULL) {// 不存在该算法名字
		printf("invalid algorithm name: %s \n", algoName);
		return 0;
	}

	// hash过程
	EVP_DigestInit(mdctx, algo); // 初始化hash函数
	EVP_DigestUpdate(mdctx, message.c_str(), message.length());// 对message进行hash
	EVP_DigestFinal(mdctx, hashValue, &hashLength);

	//printf("hash值为：\n");
	//for (unsigned int i = 0; i < hashLength; i++)
	//{
	//	hv[i] = hashValue[i];// 储存进hv
	//	printf("%02x", hashValue[i]);
	//}
	//printf("\n");

	// 收尾处理
	EVP_MD_CTX_free(mdctx); // 回收
	return 0;
}

/** ec schnorr签名 密钥生成 椭圆曲线为scep256k1
*  \param  sig_key    储存输出的密钥
*/
int ec_shnorr_key_gen(EC_KEY** sig_key) {
	EC_KEY* keypair = NULL; // 用于签名的密钥对
	int ret = 1;
	// 基于EC secp256k1自动生成公私密钥
	
	//int nid = OBJ_txt2nid("secp256k1"); // secp256k1曲线

	//secp256r1曲线 
	keypair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	// ed25519 曲线
	//keypair = EC_KEY_new_by_curve_name(NID_X25519);

	ret &= EC_KEY_generate_key(keypair); //生成密钥

	* sig_key = keypair; // 赋值
	return ret; // 成功
}


/** nonce的生成 该函数生成一个随机的k 取值范围在[1,n)之间 n为base point的秩 
 *  \param	nonce	   储存输出随机生成的数
 *  \param	range	   生成数的大小在[1,range)之间
 *  \return 1 on success and 0 fail
 */
int nonce_generation(BIGNUM* nonce,const BIGNUM* range) {
	int ret = 1;
	BIGNUM* one = BN_new(); // 值=1的大数
	if(nonce == NULL){ // 此时创建一个BIGNUM储存随机数
		nonce = BN_new();
	}
	ret &= BN_dec2bn(&one,"1");
	if (BN_cmp(range, one) !=1) { // range<=1
		ret = 0;
		return ret;
	}
	BIGNUM* k = BN_new();
	ret &= BN_sub(k, range, one); // k = range-1
	ret &= BN_rand_range(nonce, k); //[0,range-1)
	ret &= BN_add(nonce, nonce, one); // [1,range)
	return ret;
}


/** challenge的生成 = hash(R, pk, msg32)
 *  \param	e		   储存输出的challenge
 *  \param	group	   群
 *  \param  R		   commitment
 *  \param  pk         公钥
 *  \param  msg32      32bytes的待签名消息，一般表示一个消息的hash值
 *  \return 1 on success and 0 fail
 */
int schnorr_challenge(BIGNUM* e, const EC_GROUP*group, const EC_POINT* R, const EC_POINT* pk, const unsigned char* msg32) {
	const EVP_MD* algo = EVP_get_digestbyname("SHA256"); // hash算法
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // context
	unsigned char hash_value[SHA256_DIGEST_LENGTH]; //length = 32
	// 将R转成内存格式，采用的是压缩表示方法  z||x (z表示y是0是1)
	unsigned char* R_buf;
	size_t R_buf_len = EC_POINT_point2buf(group, R, POINT_CONVERSION_COMPRESSED, &R_buf, NULL);
	// 将pl转成内存格式，采用的是压缩表示方法  z||x (z表示y是0是1)
	unsigned char* pk_buf;
	size_t pk_buf_len = EC_POINT_point2buf(group, pk, POINT_CONVERSION_COMPRESSED, &pk_buf, NULL);

	//hash过程
	EVP_DigestInit(mdctx, algo);
	EVP_DigestUpdate(mdctx, R_buf, R_buf_len);
	EVP_DigestUpdate(mdctx, pk_buf, pk_buf_len);
	EVP_DigestUpdate(mdctx, msg32, 32);
	EVP_DigestFinal(mdctx, hash_value, NULL);

	//hash 值转成大数BIGNUM 存入e中
	BN_bin2bn((const unsigned char*)hash_value, SHA256_DIGEST_LENGTH, e);
	return 1; // 成功
}



/** ec schnorr签名 签名算法
 *  \param	sig64		   签名(输出的签名)
 *  \param	msg32		   32bytes的待签名消息，一般表示一个消息的hash值
 *  \param  sig_key        签名的密钥,内容包括公钥私钥等
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_sign(schnorr_sig* sig, const unsigned char* msg32, EC_KEY* sig_key) {
	// 局部变量定义
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* sk = NULL; // 私钥
	BIGNUM* e = BN_new(); // challenge
	BIGNUM* k = BN_new(); // 用于生成commitment的随机数
	BIGNUM* r_x = BN_new(), * r_y = BN_new(); // r的仿射坐标 看看能不能NULL
	int ret = 1; // 返回值 1：成功，0：失败
	const EC_GROUP* group = EC_KEY_get0_group(sig_key); // 储存椭圆曲线的一些域定义
	const BIGNUM* order = EC_GROUP_get0_order(group); // group order
	EC_POINT* R = EC_POINT_new(group); // commitment
	const EC_POINT* pk = NULL; // 公钥
	int y; // 取1，0，分别表示ec上的正负纵坐标

	// 取得公钥私钥
	sk = BN_dup(EC_KEY_get0_private_key(sig_key));
	pk = EC_KEY_get0_public_key(sig_key);
	// 随机生成k 范围在[1,n)内
	ret &= nonce_generation(k,order);
	// 计算R=k*G
	EC_POINT_mul(group, R, k, NULL, NULL, ctx); // ? ctx 直接写null可以吗
	// 取得R的仿射座标
	EC_POINT_get_affine_coordinates(group, R, r_x, r_y, ctx);
	// 设置签名中的R
	y = BN_is_odd(r_y);
	BN_bn2binpad(r_x, sig->R_x, 32);
	sig->R_y = y;

	// 计算e = H(R,pk,m)
	ret &= schnorr_challenge(e, group,R, pk, msg32);

	// 计算s = k + e*sk 并写入sig64的后半部分
	ret &= BN_mod_mul(e, e, sk, order, ctx);
	ret &= BN_mod_add(e, e, k, order, ctx);
	BN_bn2binpad(e, sig->s, 32);
	
	// 释放变量
	BN_free(sk); 
	return ret; 
}


/** ec schnorr签名 单独验证
 *  \param	sig64		   签名
 *  \param	msg32		   原消息
 *  \param  eckey          密钥（密钥对中只存了公钥）
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_verify(const schnorr_sig *sig, const unsigned char* msg32, EC_KEY* eckey) {
	BN_CTX* ctx = BN_CTX_new();
	int ret = 1;
	const EC_GROUP* group = EC_KEY_get0_group(eckey);
	const BIGNUM* order = EC_GROUP_get0_order(group);
	BIGNUM* e = BN_new(); // challenge
	const EC_POINT* pk; // 公钥
	EC_POINT* R = EC_POINT_new(group); // response 签名中的
	EC_POINT* R_compute = EC_POINT_new(group); // verifier 计算出的R
	BIGNUM* s = NULL;
	BIGNUM* rx = NULL; // 签名中的R.x
	int y;  // 对R点进行压缩的y坐标

	// 取得公钥
	pk = EC_KEY_get0_public_key(eckey); 
	// 取得签名中的R
	rx = BN_bin2bn(sig->R_x, 32, NULL);
	y = sig->R_y;
	EC_POINT_set_compressed_coordinates(group, R, rx, y,NULL);
	// 计算e = H(R,pk,m)
	ret = schnorr_challenge(e, group, R, pk, msg32);
	//取得签名中的s
	s = BN_bin2bn(sig->s, 32, s);
	// 计算R = s*G + (-e)*pk
	BN_set_negative(e, 1);
	BN_mod(e, e, order, ctx);
	EC_POINT_mul(group, R_compute, s, pk, e, NULL);

	// 比较签名中的R和我们计算出来的R是否一样
	ret = !EC_POINT_cmp(group, R, R_compute, NULL); // 相等返回1
	return ret;
}


/**  ec schnorr签名 批验证
 *  \param	n			   验证的数目
 *  \param	eckey_array    公钥数组
 *  \param  msg32_array    消息数组
 *  \param  sig64_array    签名数组
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_batch_verify(int n, EC_KEY* eckey_array[],unsigned char* msg32_array[], schnorr_sig* sig_array[]) {
	// 随机生成n个a
	int ret = 1;
	BIGNUM* a = BN_new();
	BIGNUM* s = BN_new();
	BIGNUM* e = BN_new(); // chanllenge
	BIGNUM* ae = BN_new(); // 储存中间值ai*ei
	BIGNUM* as = BN_new();// 存储中间值ai*si
	BN_CTX* ctx = BN_CTX_new(); // ctx
	BIGNUM* z = BN_new();
	BN_dec2bn(&z,"0"); // 存储z = a0 * s0+...+an-1 * sn-1; 初始值=0
	const EC_GROUP* group = NULL;
	group = EC_KEY_get0_group(eckey_array[0]); // 取得group
	EC_POINT* identity = EC_POINT_new(group); // infinity
	const BIGNUM* order = EC_GROUP_get0_order(group); // 秩
	EC_POINT* zG = EC_POINT_new(group); // zG = z*G
	EC_POINT* result = EC_POINT_new(group); // result = -z*G+a1*R1 + a2*R2 + … + an*Rn + (a1e1)*pk1 + (a2e2)* pk2 + … + (anen)* pkn
	BIGNUM* rx = BN_new(); // R 的横坐标
	const BIGNUM** bn_array = (const BIGNUM**)OPENSSL_malloc(sizeof(BIGNUM*) * (2*(size_t)n)); // 储存计算result的标量 [a0,...an-1,a0e1,...an-1en-1]
	const EC_POINT** point_array = (const EC_POINT**)OPENSSL_malloc(sizeof(EC_POINT*) * (2*(size_t)n)); // 储存计算result的点 [R0,...Rn-1,pk0,...pkn-1]
	EC_POINT* R = EC_POINT_new(group); // 存放刚从压缩形式转换成EC_point的R
	
	// 计算需要需要进行标量连乘的参数（标量、椭圆曲线上的点）
	for (int i = 0; i < n; i++) {
		// 随机生成a[i]
		ret &= nonce_generation(a, order);
		bn_array[i] = BN_dup(a); // a[i]
		// 取得签名中的R
		rx = BN_bin2bn(sig_array[i]->R_x, 32, NULL);
		EC_POINT_set_compressed_coordinates(group, R, rx, sig_array[i]->R_y, ctx);
		point_array[i] = EC_POINT_dup(R,group);
		//取得签名中的s
		s = BN_bin2bn(sig_array[i]->s, 32, NULL);
		//取得公钥pk
		point_array[i+n] = EC_KEY_get0_public_key(eckey_array[i]);
		// 计算e = H(R,pk,m)
		ret &= schnorr_challenge(e, group, point_array[i], point_array[i + n],msg32_array[i]);
		// 计算z=a1 * sa+...+an-1 * sn-1;
		BN_mod_mul(as, a, s,order, ctx); // as = ai*si
		BN_mod_add(z, z, as, order, ctx); // z = z+as
		// 计算bn_array[i+n] = ai*ei
		BN_mod_mul(ae, a, e, order, ctx);
		bn_array[i + n] = BN_dup(ae);
	}

	
	// 计算zG = -z*G
	BN_set_negative(z, 1); // z = -z
	BN_mod(z, z, order, ctx);
	EC_POINT_mul(group, zG, z, NULL, NULL, ctx);
	// 计算 (-z)*G+a1*R1 + a2*R2 + … + an*Rn + (a1e1)*pk1 + (a2e2)* pk2 + … + (anen)* pkn
	ret &= EC_POINTs_mul(group, result, z, 2*(size_t)n ,point_array,bn_array,NULL);
	ret &= EC_POINT_set_to_infinity(group, identity);
	return !EC_POINT_cmp(group, identity, result, NULL); // 相等返回1
}


int main() {
	int ret = 1; // 结果
	EC_KEY** prover_eckey = (EC_KEY**)OPENSSL_malloc(sizeof(EC_KEY*) * test_times);// Prover 的密钥
	EC_KEY** verifier_eckey = (EC_KEY**)OPENSSL_malloc(sizeof(EC_KEY*) * test_times); // Verifier的密钥（即公钥）
	schnorr_sig** sig_array = (schnorr_sig**)OPENSSL_malloc(sizeof(schnorr_sig*) * test_times);// 签名值
	unsigned char** msg_array = (unsigned char**)malloc(sizeof(unsigned char*) * test_times); // 待签名的消息
	// 单独签名和单独验证成功和失败的次数
	int vrfy_succ = 0;
	int vrfy_fail = 0;
	int sign_succ = 0;
	int sign_fail = 0;

	// 测试运行时钟周期的变量
	clock_t start_key_gen, finish_key_gen; // 密钥生成
	clock_t start_sig, finish_sig; // 签名
	clock_t start_vrfy, finish_vrfy; // 单独验签
	clock_t start_batch_vrfy, finish_batch_vrfy; // 批验签
	
	clock_t* key_gen_time = (clock_t*)malloc(sizeof(clock_t) * test_times);
	clock_t* sig_time = (clock_t*)malloc(sizeof(clock_t) * test_times);
	clock_t* vrfy_time = (clock_t*)malloc(sizeof(clock_t) * test_times);
	clock_t batch_vrfy_time = 0 ;
	clock_t multiple_vrfy_time = 0; 


	for (int i = 0; i < test_times; i++) {
		printf("第%d次测试\n", i);

		// 待签发的消息（hash值）生成
		msg_array[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32); // sha256 结果的长度32B
		digest("dog.jpg", "sha256", msg_array[i]);
		sig_array[i] = (schnorr_sig*)OPENSSL_malloc(sizeof(schnorr_sig)); // 分配一个签名结构体
		
		// prover密钥生成
		start_key_gen = clock();
		ret = ec_shnorr_key_gen(&(prover_eckey[i]));
		finish_key_gen = clock();
		key_gen_time[i] = finish_key_gen - start_key_gen;

		// 设置verifier的密钥（公钥）
		verifier_eckey[i] = EC_KEY_new();
		EC_KEY_set_group(verifier_eckey[i], EC_KEY_get0_group(prover_eckey[i]));
		EC_KEY_set_public_key(verifier_eckey[i], EC_KEY_get0_public_key(prover_eckey[i]));

		// schnoor 签名
		start_sig = clock();
		ret = ec_shnorr_sign(sig_array[i], msg_array[i], prover_eckey[i]);
		finish_sig = clock();
		sig_time[i] = finish_sig - start_sig;
		if (ret == 1) { // 签名成功
			sign_succ++;
		}
		else {
			sign_fail++;
		}

		// schnoor 单独验签
		start_vrfy = clock();
		ret = ec_shnorr_verify(sig_array[i], msg_array[i], verifier_eckey[i]);
		finish_vrfy = clock();
		vrfy_time[i] = finish_vrfy - start_vrfy;
		multiple_vrfy_time += vrfy_time[i];
		if (ret == 1) {
			vrfy_succ++;
		}
		else {
			vrfy_fail++;
		}
	}
	printf("椭圆曲线：secp256r1\n");
	printf("签名：成功=%d次,失败=%d次\n", sign_succ, sign_fail);
	printf("单独验签：成功=%d次,失败=%d次\n", vrfy_succ, vrfy_fail);

	
	// schnorr 批验证
	start_batch_vrfy = clock();
	ret = ec_shnorr_batch_verify(test_times, verifier_eckey, msg_array, sig_array);
	finish_batch_vrfy = clock();
	batch_vrfy_time = finish_batch_vrfy - start_batch_vrfy;
	if (ret == 1) {
		printf("批验签成功!\n");
	}
	else {
		printf("批验签失败!\n");
	}


	// 输出运行时间测试
	printf("运行%d次，密钥生成时钟周期数中值：%ld\n",test_times, mid_value(key_gen_time, test_times));
	printf("运行%d次，签名时钟周期数中值：%ld\n", test_times, mid_value(sig_time, test_times));
	printf("运行%d次，单次验证时钟周期数中值：%ld\n", test_times, mid_value(vrfy_time, test_times));
	printf("运行%d次，批验证时钟周期数：%ld\n", test_times, batch_vrfy_time);
	printf("运行%d次，单次验证运行多次时钟周期数：%ld\n", test_times, multiple_vrfy_time);


	// 释放变量
	for (int i = 0; i < test_times; i++) {
		free(msg_array[i]);
		OPENSSL_free(prover_eckey[i]);
		OPENSSL_free(verifier_eckey[i]);
		OPENSSL_free(sig_array[i]);
	}
	free(msg_array);
	free(key_gen_time);
	free(sig_time);
	free(vrfy_time);
	OPENSSL_free(prover_eckey);
	OPENSSL_free(verifier_eckey);
	OPENSSL_free(sig_array);

	return 0;
}

#endif // !EC_SCHNORR_C
