#ifndef __CPPOPENSSL_RSA_HPP__
#define __CPPOPENSSL_RSA_HPP__

#include "global.hpp"

typedef struct rsa_st RSA;

namespace CppOpenSSL
{
class CppRSA
{
public:
	enum RSA_METHOD
	{
		RSA_PUB_ENC,	// RSA_public_encrypt
		RSA_PUB_DEC,	// RSA_public_decrypt
		RSA_PRIV_ENC,	// RSA_private_encrypt
		RSA_PRIV_DEC	// RSA_private_decrypt
	};

	enum RSA_PADDING
	{
		RSA_PKCS1		= 1,	// RSA_PKCS1_PADDING
		RSA_SSLV23		= 2,	// RSA_SSLV23_PADDING
		RSA_NO			= 3,	// RSA_NO_PADDING
		RSA_PKCS1_OAEP	= 4,	// RSA_PKCS1_OAEP_PADDING
		RSA_X931		= 5		// RSA_X931_PADDING
	};

public:
	CppRSA();

	~CppRSA();

public:
	static CppPtr<RSA> GenerateKey(int bits, unsigned int e);

	static bool BackupKey(RSA* key, CppPtr<char>& n, unsigned int& e, CppPtr<char>& d);

	static CppPtr<RSA> RestoreKey(const char* n, unsigned int e, const char* d);

	int Init(int method, const unsigned char* from, int flen, RSA* key, int padding);

	bool Update(unsigned char* to);

	bool Final();

private:
	typedef int (*_OPENSSL_RSA_FP)(int, const unsigned char*, unsigned char*, RSA*, int);

private:
	static _OPENSSL_RSA_FP _fp[4];
	int _method;
	const unsigned char* _from;
	int _flen;
	RSA* _key;
	int _padding;
	int _mlen;
	int _blen;
	int _blo;
	unsigned char* _to;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_RSA_HPP__
