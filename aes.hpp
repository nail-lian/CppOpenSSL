#ifndef __CPPOPENSSL_AES_HPP__
#define __CPPOPENSSL_AES_HPP__

#include "global.hpp"

typedef struct aes_key_st AES_KEY;

namespace CppOpenSSL
{
class CppAES
{
public:
	enum AES_METHOD
	{
		AES_ECB,	// AES_ecb_encrypt
		AES_CBC,	// AES_cbc_encrypt
		AES_CFB,	// AES_cfb128_encrypt
		AES_OFB,	// AES_ofb128_encrypt
		AES_CTR		// AES_ctr128_encrypt
	};

public:
	CppAES();

	~CppAES();

public:
	static bool GenerateKey(unsigned char* key, int klen);

	int Init(int method, const unsigned char* from, int flen, const unsigned char* key, int klen, unsigned char ivec[16], bool enc);

	void Update(unsigned char* to);

	void Final();

private:
	int _method;
	const unsigned char* _from;
	int _flen;
	unsigned char _ivec[16];
	int _enc;
	CppPtr<AES_KEY> _key;
	int _blo;
	unsigned char* _to;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_AES_HPP__
