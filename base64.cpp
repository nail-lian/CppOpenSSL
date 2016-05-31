#include "base64.hpp"

#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace CppOpenSSL
{
int CppBASE64::LengthOfEncode(int flen, bool nl)
{
	int tlen = ((flen - 1) / 3 + 1) * 4;

	if (nl)
	{
		tlen += (tlen - 1) / 64 + 1;
	}

	return tlen;
}

int CppBASE64::LengthOfDecode(int flen, bool nl)
{
	if (nl)
	{
		flen -= (flen - 1) / 65 + 1;
	}

	int tlen = flen / 4 * 3;

	return tlen;
}

bool CppBASE64::Encode(const unsigned char* from, int flen, bool nl, char* to)
{
	CppPtr<BIO> bio_base64(BIO_new(BIO_f_base64()), BIO_free_all);
	if (bio_base64 == NULL)
	{
		return false;
	}

	if (!nl)
	{
		BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);
	}

	BIO* bio_mem = BIO_new(BIO_s_mem());
	if (bio_mem == NULL)
	{
		return false;
	}

	BIO_push(bio_base64, bio_mem);

	if (BIO_write(bio_base64, from, flen) <= 0)
	{
		return false;
	}

	BIO_flush(bio_base64);

	BUF_MEM* buf_mem = NULL;

	BIO_get_mem_ptr(bio_base64, &buf_mem);
	memcpy(to, buf_mem->data, buf_mem->length);

	return true;
}

bool CppBASE64::Decode(const char* from, int flen, bool nl, unsigned char* to)
{
	CppPtr<BIO> bio_base64(BIO_new(BIO_f_base64()), BIO_free_all);
	if (bio_base64 == NULL)
	{
		return false;
	}

	if (!nl)
	{
		BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);
	}

	BIO* bio_mem = BIO_new_mem_buf(const_cast<char*>(from), flen);
	if (bio_mem == NULL)
	{
		return false;
	}

	BIO_push(bio_base64, bio_mem);

	if (BIO_read(bio_base64, to, LengthOfDecode(flen, nl)) <= 0)
	{
		return false;
	}

	return true;
}
}	// CppOpenSSL
