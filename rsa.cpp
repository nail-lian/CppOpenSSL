#include "rsa.hpp"

#include <utility>

#include <openssl/rsa.h>

namespace CppOpenSSL
{
CppRSA::_OPENSSL_RSA_FP CppRSA::_fp[4] = {RSA_public_encrypt, RSA_public_decrypt, RSA_private_encrypt, RSA_private_decrypt};

CppRSA::CppRSA() :
_method(0),
_from(NULL),
_flen(0),
_key(NULL),
_padding(0),
_mlen(0),
_blen(0),
_blo(0),
_to(NULL)
{
}

CppRSA::~CppRSA()
{
}

CppPtr<RSA> CppRSA::GenerateKey(int bits, unsigned int e)
{
	return CppPtr<RSA>(RSA_generate_key(bits, e, NULL, NULL), RSA_free);
}

bool CppRSA::BackupKey(RSA* key, CppPtr<char>& n, unsigned int& e, CppPtr<char>& d)
{
	CppPtr<char> the_n(BN_bn2hex(key->n), [](char* ptr) { OPENSSL_freeFunc(ptr); });
	unsigned int the_e = BN_get_word(key->e);
	if (the_n == NULL || the_e == -1)
	{
		return false;
	}

	n = std::move(the_n);
	e = the_e;

	if (key->d != NULL)
	{
		CppPtr<char> the_d(BN_bn2hex(key->d), [](char* ptr) { OPENSSL_freeFunc(ptr); });
		if (the_d == NULL)
		{
			return false;
		}

		d = std::move(the_d);
	}

	return true;
}

CppPtr<RSA> CppRSA::RestoreKey(const char* n, unsigned int e, const char* d)
{
	CppPtr<RSA> key(RSA_new(), RSA_free);
	if (key == NULL)
	{
		return CppPtr<RSA>();
	}

	CppPtr<BIGNUM> bn_n(BN_new(), BN_free);
	CppPtr<BIGNUM> bn_e(BN_new(), BN_free);
	if (bn_n == NULL || bn_e == NULL)
	{
		return CppPtr<RSA>();
	}

	BN_hex2bn(&bn_n, n);
	BN_set_word(bn_e, e);

	key->n = bn_n.Release();
	key->e = bn_e.Release();

	if (d != NULL)
	{
		CppPtr<BIGNUM> bn_d(BN_new(), BN_free);
		if (bn_d == NULL)
		{
			return CppPtr<RSA>();
		}

		BN_hex2bn(&bn_d, d);

		key->d = bn_d.Release();
	}

	return std::move(key);
}

int CppRSA::Init(int method, const unsigned char* from, int flen, RSA* key, int padding)
{
	_method = method;
	_from = from;
	_flen = flen;
	_key = key;
	_padding = padding;

	_mlen = RSA_size(_key);

	switch (_padding)
	{
	case RSA_PKCS1:
	case RSA_SSLV23:
		_blen = _mlen - 11;
		break;
	case RSA_NO:
		_blen = _mlen;
		break;
	case RSA_PKCS1_OAEP:
		_blen = _mlen - 41;
		break;
	}

	int tlen = 0;

	if (_method == RSA_PUB_ENC || _method == RSA_PRIV_ENC)
	{
		_blo = _flen / _blen + 1;
		tlen = _mlen * _blo;
	}
	else
	{
		_blo = _flen / _mlen;
		tlen = _blen * _blo;
	}

	return tlen;
}

bool CppRSA::Update(unsigned char* to)
{
	_to = to;

	if (_method == RSA_PUB_ENC || _method == RSA_PRIV_ENC)
	{
		for (int i = 0; i < _blo - 1; ++i)
		{
			if (_fp[_method](_blen, _from + _blen * i, _to + _mlen * i, _key, _padding) == -1)
			{
				return false;
			}
		}
	}
	else
	{
		for (int i = 0; i < _blo; ++i)
		{
			if (_fp[_method](_mlen, _from + _mlen * i, _to + _blen * i, _key, _padding) == -1)
			{
				return false;
			}
		}
	}

	return true;
}

bool CppRSA::Final()
{
	if (_method == RSA_PUB_ENC || _method == RSA_PRIV_ENC)
	{
		CppPtr<unsigned char> buff(CppAlloc<unsigned char>(_blen), CppFree<unsigned char>);
		int len = _flen - _blen * (_blo - 1);

		memcpy(buff, _from + _blen * (_blo - 1), len);
		memset(buff + len, _blen - len, _blen - len);

		if (_fp[_method](_blen, buff, _to + _mlen * (_blo - 1), _key, _padding) == -1)
		{
			return false;
		}
	}

	return true;
}
}	// CppOpenSSL
