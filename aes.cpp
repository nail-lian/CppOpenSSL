#include "aes.hpp"

#include <openssl/rand.h>
#include <openssl/aes.h>

namespace CppOpenSSL
{
CppAES::CppAES() :
_method(0),
_from(NULL),
_flen(0),
_enc(0),
_key(NULL, CppFree<AES_KEY>),
_blo(0),
_to(NULL)
{
	memset(_ivec, 0, 16);
}

CppAES::~CppAES()
{
}

bool CppAES::GenerateKey(unsigned char* key, int klen)
{
	return RAND_bytes(key, klen) == 1;
}

int CppAES::Init(int method, const unsigned char* from, int flen, const unsigned char* key, int klen, unsigned char ivec[16], bool enc)
{
	_method = method;
	_from = from;
	_flen = flen;
	if (ivec != NULL) memcpy(_ivec, ivec, 16);
	_enc = enc ? AES_ENCRYPT : AES_DECRYPT;

	_key = CppAlloc<AES_KEY>();

	if (_enc == AES_ENCRYPT)
	{
		if (AES_set_encrypt_key(key, 8 * klen, _key) != 0)
		{
			return 0;
		}

		_blo = _flen / 16 + 1;
	}
	else
	{
		if (AES_set_decrypt_key(key, 8 * klen, _key) != 0)
		{
			return 0;
		}

		_blo = _flen / 16;
	}

	return 16 * _blo;
}

void CppAES::Update(unsigned char* to)
{
	_to = to;

	if (_method == AES_ECB)
	{
		int blo = _enc == AES_ENCRYPT ? _blo - 1 : _blo;

		for (int i = 0; i < blo; ++i)
		{
			AES_ecb_encrypt(_from + 16 * i, _to + 16 * i, _key, _enc);
		}
	}
	else if (_method == AES_CBC)
	{
		AES_cbc_encrypt(_from, _to, _flen, _key, _ivec, _enc);
	}
}

void CppAES::Final()
{
	if (_method == AES_ECB)
	{
		if (_enc == AES_ENCRYPT)
		{
			unsigned char buff[16] = {};
			int len = _flen - 16 * (_blo - 1);

			memcpy(buff, _from + 16 * (_blo - 1), len);
			memset(buff + len, 16 - len, 16 - len);

			AES_ecb_encrypt(buff, _to + 16 * (_blo - 1), _key, _enc);
		}
	}
}
}	// CppOpenSSL
