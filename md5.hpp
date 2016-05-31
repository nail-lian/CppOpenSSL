#ifndef __CPPOPENSSL_MD5_HPP__
#define __CPPOPENSSL_MD5_HPP__

#include "global.hpp"

typedef struct MD5state_st MD5_CTX;

namespace CppOpenSSL
{
class CppMD5
{
public:
	CppMD5();

	~CppMD5();

public:
	static void Transform(const unsigned char in[16], char out[32]);

	bool Init();

	bool Update(const unsigned char* from, int flen);

	bool Final(unsigned char to[16]);

private:
	CppPtr<MD5_CTX> _ctx;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_MD5_HPP__
