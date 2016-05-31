#ifndef __CPPOPENSSL_PEM_HPP__
#define __CPPOPENSSL_PEM_HPP__

#include "global.hpp"

typedef struct rsa_st RSA;

namespace CppOpenSSL
{
class CppPEM
{
public:
	static CppPtr<RSA> ReadRSAPubKey(const char* file);

	static CppPtr<RSA> ReadRSAPrivKey(const char* file);

	static bool WriteRSAPubKey(const char* file, RSA* key);

	static bool WriteRSAPrivKey(const char* file, RSA* key);
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_PEM_HPP__
