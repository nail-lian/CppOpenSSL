#include "md5.hpp"

#include <cstdio>

#include <openssl/md5.h>

namespace CppOpenSSL
{
CppMD5::CppMD5() :
_ctx(NULL, CppFree<MD5_CTX>)
{
}

CppMD5::~CppMD5()
{
}

void CppMD5::Transform(const unsigned char in[16], char out[32])
{
	for (int i = 0; i < 16; ++i)
	{
		char str[4] = {};

		sprintf(str, "%02x", in[i]);

		out[2 * i] = str[0];
		out[2 * i + 1] = str[1];
	}
}

bool CppMD5::Init()
{
	_ctx = CppAlloc<MD5_CTX>();

	return MD5_Init(_ctx) == 1;
}

bool CppMD5::Update(const unsigned char* from, int flen)
{
	return MD5_Update(_ctx, from, flen) == 1;
}

bool CppMD5::Final(unsigned char to[16])
{
	return MD5_Final(to, _ctx) == 1;
}
}	// CppOpenSSL
