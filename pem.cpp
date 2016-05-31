#include "pem.hpp"

#include <utility>

#include <openssl/pem.h>

namespace CppOpenSSL
{
CppPtr<RSA> CppPEM::ReadRSAPubKey(const char* file)
{
	CppPtr<BIO> bio(BIO_new_file(file, "r"), [](BIO* ptr) { BIO_free(ptr); });
	if (bio == NULL)
	{
		return CppPtr<RSA>();
	}

	CppPtr<RSA> key(PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL), RSA_free);
	if (key == NULL)
	{
		return CppPtr<RSA>();
	}

	return std::move(key);
}

CppPtr<RSA> CppPEM::ReadRSAPrivKey(const char* file)
{
	CppPtr<BIO> bio(BIO_new_file(file, "r"), [](BIO* ptr) { BIO_free(ptr); });
	if (bio == NULL)
	{
		return CppPtr<RSA>();
	}

	CppPtr<RSA> key(PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL), RSA_free);
	if (key == NULL)
	{
		return CppPtr<RSA>();
	}

	return std::move(key);
}

bool CppPEM::WriteRSAPubKey(const char* file, RSA* key)
{
	CppPtr<BIO> bio(BIO_new_file(file, "w"), [](BIO* ptr) { BIO_free(ptr); });
	if (bio == NULL)
	{
		return false;
	}

	if (PEM_write_bio_RSAPublicKey(bio, key) == 0)
	{
		return false;
	}

	return true;
}

bool CppPEM::WriteRSAPrivKey(const char* file, RSA* key)
{
	CppPtr<BIO> bio(BIO_new_file(file, "w"), [](BIO* ptr) { BIO_free(ptr); });
	if (bio == NULL)
	{
		return false;
	}

	if (PEM_write_bio_RSAPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 0)
	{
		return false;
	}

	return true;
}
}	// CppOpenSSL
