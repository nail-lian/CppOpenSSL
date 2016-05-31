#ifndef __CPPOPENSSL_BASE64_HPP__
#define __CPPOPENSSL_BASE64_HPP__

#include "global.hpp"

namespace CppOpenSSL
{
class CppBASE64
{
public:
	static int LengthOfEncode(int flen, bool nl);

	static int LengthOfDecode(int flen, bool nl);

	static bool Encode(const unsigned char* from, int flen, bool nl, char* to);

	static bool Decode(const char* from, int flen, bool nl, unsigned char* to);
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_BASE64_HPP__
