
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

const int test_times = 10000; // ���Դ���

// �ȽϺ���
int cmpfunc(const void* a, const void* b) {
	return(*(clock_t*)a - *(clock_t*)b);
}

// ȡ��������ʱ�����λ��
int mid_value(clock_t* array, int len) {
	qsort((void*)array, (size_t)len, sizeof(clock_t), cmpfunc);
	if (len % 2) { // odd
		return array[len / 2];
	}
	else {
		return (array[len / 2 - 1] + array[len / 2]) / 2;
	}
}

/** ���ļ�����hash�ĺ���
*  \param  fileName    �ļ�����
*  \param  algoName    hash�㷨����
*  \param  hv		   �������hashֵ
*/
int digest(const char* fileName, const char* algoName, unsigned char* hv) {

	const EVP_MD* algo = NULL;
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // contex
	unsigned char hashValue[EVP_MAX_MD_SIZE]; // hashֵ
	memset(hashValue, 0, EVP_MAX_MD_SIZE);
	unsigned int hashLength; //hashֵ����
	string message;


	//�ļ����ݶ�ȡ
	ifstream ifile; // �����ļ���ifile������
	ifile.open(fileName, std::fstream::binary);//��������ʽ��ȡ
	char c;
	while (ifile.get(c))
		message += c; // ���ļ����ݴ��浽message��

	// ���㷨����ȡ���㷨
	algo = EVP_get_digestbyname(algoName);
	if (algo == NULL) {// �����ڸ��㷨����
		printf("invalid algorithm name: %s \n", algoName);
		return 0;
	}

	// hash����
	EVP_DigestInit(mdctx, algo); // ��ʼ��hash����
	EVP_DigestUpdate(mdctx, message.c_str(), message.length());// ��message����hash
	EVP_DigestFinal(mdctx, hashValue, &hashLength);

	//printf("hashֵΪ��\n");
	//for (unsigned int i = 0; i < hashLength; i++)
	//{
	//	hv[i] = hashValue[i];// �����hv
	//	printf("%02x", hashValue[i]);
	//}
	//printf("\n");

	// ��β����
	EVP_MD_CTX_free(mdctx); // ����
	return 0;
}

/** ec schnorrǩ�� ��Կ���� ��Բ����Ϊscep256k1
*  \param  sig_key    �����������Կ
*/
int ec_shnorr_key_gen(EC_KEY** sig_key) {
	EC_KEY* keypair = NULL; // ����ǩ������Կ��
	int ret = 1;
	// ����EC secp256k1�Զ����ɹ�˽��Կ
	
	//int nid = OBJ_txt2nid("secp256k1"); // secp256k1����

	//secp256r1���� 
	keypair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	// ed25519 ����
	//keypair = EC_KEY_new_by_curve_name(NID_X25519);

	ret &= EC_KEY_generate_key(keypair); //������Կ

	* sig_key = keypair; // ��ֵ
	return ret; // �ɹ�
}


/** nonce������ �ú�������һ�������k ȡֵ��Χ��[1,n)֮�� nΪbase point���� 
 *  \param	nonce	   �������������ɵ���
 *  \param	range	   �������Ĵ�С��[1,range)֮��
 *  \return 1 on success and 0 fail
 */
int nonce_generation(BIGNUM* nonce,const BIGNUM* range) {
	int ret = 1;
	BIGNUM* one = BN_new(); // ֵ=1�Ĵ���
	if(nonce == NULL){ // ��ʱ����һ��BIGNUM���������
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


/** challenge������ = hash(R, pk, msg32)
 *  \param	e		   ���������challenge
 *  \param	group	   Ⱥ
 *  \param  R		   commitment
 *  \param  pk         ��Կ
 *  \param  msg32      32bytes�Ĵ�ǩ����Ϣ��һ���ʾһ����Ϣ��hashֵ
 *  \return 1 on success and 0 fail
 */
int schnorr_challenge(BIGNUM* e, const EC_GROUP*group, const EC_POINT* R, const EC_POINT* pk, const unsigned char* msg32) {
	const EVP_MD* algo = EVP_get_digestbyname("SHA256"); // hash�㷨
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // context
	unsigned char hash_value[SHA256_DIGEST_LENGTH]; //length = 32
	// ��Rת���ڴ��ʽ�����õ���ѹ����ʾ����  z||x (z��ʾy��0��1)
	unsigned char* R_buf;
	size_t R_buf_len = EC_POINT_point2buf(group, R, POINT_CONVERSION_COMPRESSED, &R_buf, NULL);
	// ��plת���ڴ��ʽ�����õ���ѹ����ʾ����  z||x (z��ʾy��0��1)
	unsigned char* pk_buf;
	size_t pk_buf_len = EC_POINT_point2buf(group, pk, POINT_CONVERSION_COMPRESSED, &pk_buf, NULL);

	//hash����
	EVP_DigestInit(mdctx, algo);
	EVP_DigestUpdate(mdctx, R_buf, R_buf_len);
	EVP_DigestUpdate(mdctx, pk_buf, pk_buf_len);
	EVP_DigestUpdate(mdctx, msg32, 32);
	EVP_DigestFinal(mdctx, hash_value, NULL);

	//hash ֵת�ɴ���BIGNUM ����e��
	BN_bin2bn((const unsigned char*)hash_value, SHA256_DIGEST_LENGTH, e);
	return 1; // �ɹ�
}



/** ec schnorrǩ�� ǩ���㷨
 *  \param	sig64		   ǩ��(�����ǩ��)
 *  \param	msg32		   32bytes�Ĵ�ǩ����Ϣ��һ���ʾһ����Ϣ��hashֵ
 *  \param  sig_key        ǩ������Կ,���ݰ�����Կ˽Կ��
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_sign(schnorr_sig* sig, const unsigned char* msg32, EC_KEY* sig_key) {
	// �ֲ���������
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* sk = NULL; // ˽Կ
	BIGNUM* e = BN_new(); // challenge
	BIGNUM* k = BN_new(); // ��������commitment�������
	BIGNUM* r_x = BN_new(), * r_y = BN_new(); // r�ķ������� �����ܲ���NULL
	int ret = 1; // ����ֵ 1���ɹ���0��ʧ��
	const EC_GROUP* group = EC_KEY_get0_group(sig_key); // ������Բ���ߵ�һЩ����
	const BIGNUM* order = EC_GROUP_get0_order(group); // group order
	EC_POINT* R = EC_POINT_new(group); // commitment
	const EC_POINT* pk = NULL; // ��Կ
	int y; // ȡ1��0���ֱ��ʾec�ϵ�����������

	// ȡ�ù�Կ˽Կ
	sk = BN_dup(EC_KEY_get0_private_key(sig_key));
	pk = EC_KEY_get0_public_key(sig_key);
	// �������k ��Χ��[1,n)��
	ret &= nonce_generation(k,order);
	// ����R=k*G
	EC_POINT_mul(group, R, k, NULL, NULL, ctx); // ? ctx ֱ��дnull������
	// ȡ��R�ķ�������
	EC_POINT_get_affine_coordinates(group, R, r_x, r_y, ctx);
	// ����ǩ���е�R
	y = BN_is_odd(r_y);
	BN_bn2binpad(r_x, sig->R_x, 32);
	sig->R_y = y;

	// ����e = H(R,pk,m)
	ret &= schnorr_challenge(e, group,R, pk, msg32);

	// ����s = k + e*sk ��д��sig64�ĺ�벿��
	ret &= BN_mod_mul(e, e, sk, order, ctx);
	ret &= BN_mod_add(e, e, k, order, ctx);
	BN_bn2binpad(e, sig->s, 32);
	
	// �ͷű���
	BN_free(sk); 
	return ret; 
}


/** ec schnorrǩ�� ������֤
 *  \param	sig64		   ǩ��
 *  \param	msg32		   ԭ��Ϣ
 *  \param  eckey          ��Կ����Կ����ֻ���˹�Կ��
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_verify(const schnorr_sig *sig, const unsigned char* msg32, EC_KEY* eckey) {
	BN_CTX* ctx = BN_CTX_new();
	int ret = 1;
	const EC_GROUP* group = EC_KEY_get0_group(eckey);
	const BIGNUM* order = EC_GROUP_get0_order(group);
	BIGNUM* e = BN_new(); // challenge
	const EC_POINT* pk; // ��Կ
	EC_POINT* R = EC_POINT_new(group); // response ǩ���е�
	EC_POINT* R_compute = EC_POINT_new(group); // verifier �������R
	BIGNUM* s = NULL;
	BIGNUM* rx = NULL; // ǩ���е�R.x
	int y;  // ��R�����ѹ����y����

	// ȡ�ù�Կ
	pk = EC_KEY_get0_public_key(eckey); 
	// ȡ��ǩ���е�R
	rx = BN_bin2bn(sig->R_x, 32, NULL);
	y = sig->R_y;
	EC_POINT_set_compressed_coordinates(group, R, rx, y,NULL);
	// ����e = H(R,pk,m)
	ret = schnorr_challenge(e, group, R, pk, msg32);
	//ȡ��ǩ���е�s
	s = BN_bin2bn(sig->s, 32, s);
	// ����R = s*G + (-e)*pk
	BN_set_negative(e, 1);
	BN_mod(e, e, order, ctx);
	EC_POINT_mul(group, R_compute, s, pk, e, NULL);

	// �Ƚ�ǩ���е�R�����Ǽ��������R�Ƿ�һ��
	ret = !EC_POINT_cmp(group, R, R_compute, NULL); // ��ȷ���1
	return ret;
}


/**  ec schnorrǩ�� ����֤
 *  \param	n			   ��֤����Ŀ
 *  \param	eckey_array    ��Կ����
 *  \param  msg32_array    ��Ϣ����
 *  \param  sig64_array    ǩ������
 *  \return 1 on success and 0 fail
 */
int ec_shnorr_batch_verify(int n, EC_KEY* eckey_array[],unsigned char* msg32_array[], schnorr_sig* sig_array[]) {
	// �������n��a
	int ret = 1;
	BIGNUM* a = BN_new();
	BIGNUM* s = BN_new();
	BIGNUM* e = BN_new(); // chanllenge
	BIGNUM* ae = BN_new(); // �����м�ֵai*ei
	BIGNUM* as = BN_new();// �洢�м�ֵai*si
	BN_CTX* ctx = BN_CTX_new(); // ctx
	BIGNUM* z = BN_new();
	BN_dec2bn(&z,"0"); // �洢z = a0 * s0+...+an-1 * sn-1; ��ʼֵ=0
	const EC_GROUP* group = NULL;
	group = EC_KEY_get0_group(eckey_array[0]); // ȡ��group
	EC_POINT* identity = EC_POINT_new(group); // infinity
	const BIGNUM* order = EC_GROUP_get0_order(group); // ��
	EC_POINT* zG = EC_POINT_new(group); // zG = z*G
	EC_POINT* result = EC_POINT_new(group); // result = -z*G+a1*R1 + a2*R2 + �� + an*Rn + (a1e1)*pk1 + (a2e2)* pk2 + �� + (anen)* pkn
	BIGNUM* rx = BN_new(); // R �ĺ�����
	const BIGNUM** bn_array = (const BIGNUM**)OPENSSL_malloc(sizeof(BIGNUM*) * (2*(size_t)n)); // �������result�ı��� [a0,...an-1,a0e1,...an-1en-1]
	const EC_POINT** point_array = (const EC_POINT**)OPENSSL_malloc(sizeof(EC_POINT*) * (2*(size_t)n)); // �������result�ĵ� [R0,...Rn-1,pk0,...pkn-1]
	EC_POINT* R = EC_POINT_new(group); // ��Ÿմ�ѹ����ʽת����EC_point��R
	
	// ������Ҫ��Ҫ���б������˵Ĳ�������������Բ�����ϵĵ㣩
	for (int i = 0; i < n; i++) {
		// �������a[i]
		ret &= nonce_generation(a, order);
		bn_array[i] = BN_dup(a); // a[i]
		// ȡ��ǩ���е�R
		rx = BN_bin2bn(sig_array[i]->R_x, 32, NULL);
		EC_POINT_set_compressed_coordinates(group, R, rx, sig_array[i]->R_y, ctx);
		point_array[i] = EC_POINT_dup(R,group);
		//ȡ��ǩ���е�s
		s = BN_bin2bn(sig_array[i]->s, 32, NULL);
		//ȡ�ù�Կpk
		point_array[i+n] = EC_KEY_get0_public_key(eckey_array[i]);
		// ����e = H(R,pk,m)
		ret &= schnorr_challenge(e, group, point_array[i], point_array[i + n],msg32_array[i]);
		// ����z=a1 * sa+...+an-1 * sn-1;
		BN_mod_mul(as, a, s,order, ctx); // as = ai*si
		BN_mod_add(z, z, as, order, ctx); // z = z+as
		// ����bn_array[i+n] = ai*ei
		BN_mod_mul(ae, a, e, order, ctx);
		bn_array[i + n] = BN_dup(ae);
	}

	
	// ����zG = -z*G
	BN_set_negative(z, 1); // z = -z
	BN_mod(z, z, order, ctx);
	EC_POINT_mul(group, zG, z, NULL, NULL, ctx);
	// ���� (-z)*G+a1*R1 + a2*R2 + �� + an*Rn + (a1e1)*pk1 + (a2e2)* pk2 + �� + (anen)* pkn
	ret &= EC_POINTs_mul(group, result, z, 2*(size_t)n ,point_array,bn_array,NULL);
	ret &= EC_POINT_set_to_infinity(group, identity);
	return !EC_POINT_cmp(group, identity, result, NULL); // ��ȷ���1
}


int main() {
	int ret = 1; // ���
	EC_KEY** prover_eckey = (EC_KEY**)OPENSSL_malloc(sizeof(EC_KEY*) * test_times);// Prover ����Կ
	EC_KEY** verifier_eckey = (EC_KEY**)OPENSSL_malloc(sizeof(EC_KEY*) * test_times); // Verifier����Կ������Կ��
	schnorr_sig** sig_array = (schnorr_sig**)OPENSSL_malloc(sizeof(schnorr_sig*) * test_times);// ǩ��ֵ
	unsigned char** msg_array = (unsigned char**)malloc(sizeof(unsigned char*) * test_times); // ��ǩ������Ϣ
	// ����ǩ���͵�����֤�ɹ���ʧ�ܵĴ���
	int vrfy_succ = 0;
	int vrfy_fail = 0;
	int sign_succ = 0;
	int sign_fail = 0;

	// ��������ʱ�����ڵı���
	clock_t start_key_gen, finish_key_gen; // ��Կ����
	clock_t start_sig, finish_sig; // ǩ��
	clock_t start_vrfy, finish_vrfy; // ������ǩ
	clock_t start_batch_vrfy, finish_batch_vrfy; // ����ǩ
	
	clock_t* key_gen_time = (clock_t*)malloc(sizeof(clock_t) * test_times);
	clock_t* sig_time = (clock_t*)malloc(sizeof(clock_t) * test_times);
	clock_t* vrfy_time = (clock_t*)malloc(sizeof(clock_t) * test_times);
	clock_t batch_vrfy_time = 0 ;
	clock_t multiple_vrfy_time = 0; 


	for (int i = 0; i < test_times; i++) {
		printf("��%d�β���\n", i);

		// ��ǩ������Ϣ��hashֵ������
		msg_array[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32); // sha256 ����ĳ���32B
		digest("dog.jpg", "sha256", msg_array[i]);
		sig_array[i] = (schnorr_sig*)OPENSSL_malloc(sizeof(schnorr_sig)); // ����һ��ǩ���ṹ��
		
		// prover��Կ����
		start_key_gen = clock();
		ret = ec_shnorr_key_gen(&(prover_eckey[i]));
		finish_key_gen = clock();
		key_gen_time[i] = finish_key_gen - start_key_gen;

		// ����verifier����Կ����Կ��
		verifier_eckey[i] = EC_KEY_new();
		EC_KEY_set_group(verifier_eckey[i], EC_KEY_get0_group(prover_eckey[i]));
		EC_KEY_set_public_key(verifier_eckey[i], EC_KEY_get0_public_key(prover_eckey[i]));

		// schnoor ǩ��
		start_sig = clock();
		ret = ec_shnorr_sign(sig_array[i], msg_array[i], prover_eckey[i]);
		finish_sig = clock();
		sig_time[i] = finish_sig - start_sig;
		if (ret == 1) { // ǩ���ɹ�
			sign_succ++;
		}
		else {
			sign_fail++;
		}

		// schnoor ������ǩ
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
	printf("��Բ���ߣ�secp256r1\n");
	printf("ǩ�����ɹ�=%d��,ʧ��=%d��\n", sign_succ, sign_fail);
	printf("������ǩ���ɹ�=%d��,ʧ��=%d��\n", vrfy_succ, vrfy_fail);

	
	// schnorr ����֤
	start_batch_vrfy = clock();
	ret = ec_shnorr_batch_verify(test_times, verifier_eckey, msg_array, sig_array);
	finish_batch_vrfy = clock();
	batch_vrfy_time = finish_batch_vrfy - start_batch_vrfy;
	if (ret == 1) {
		printf("����ǩ�ɹ�!\n");
	}
	else {
		printf("����ǩʧ��!\n");
	}


	// �������ʱ�����
	printf("����%d�Σ���Կ����ʱ����������ֵ��%ld\n",test_times, mid_value(key_gen_time, test_times));
	printf("����%d�Σ�ǩ��ʱ����������ֵ��%ld\n", test_times, mid_value(sig_time, test_times));
	printf("����%d�Σ�������֤ʱ����������ֵ��%ld\n", test_times, mid_value(vrfy_time, test_times));
	printf("����%d�Σ�����֤ʱ����������%ld\n", test_times, batch_vrfy_time);
	printf("����%d�Σ�������֤���ж��ʱ����������%ld\n", test_times, multiple_vrfy_time);


	// �ͷű���
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
