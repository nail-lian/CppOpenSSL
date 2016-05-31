#ifndef __CPPOPENSSL_GLOBAL_HPP__
#define __CPPOPENSSL_GLOBAL_HPP__

#include <cstring>
#include <cstddef>

#include <new>

namespace CppOpenSSL
{
template <typename T>
inline T* CppAlloc(int n = 1)
{
	T* ptr = new T[n];
	memset(ptr, 0, sizeof(T) * n);
	return ptr;
}

template <typename T>
inline void CppFree(T* ptr)
{
	delete[] ptr;
}

template <typename T>
class CppPtr
{
public:
	typedef void (*DELETER_FP)(T*);

public:
	CppPtr(T* ptr = NULL, DELETER_FP deleter = NULL) :
	_ptr(ptr),
	_deleter(deleter)
	{
	}

	CppPtr(CppPtr<T>&& other) :
	_ptr(other._ptr),
	_deleter(other._deleter)
	{
		other.Release();
	}

	~CppPtr()
	{
		Reset();
	}

	CppPtr<T>& operator =(T* ptr)
	{
		Reset(ptr);
		return *this;
	}

	CppPtr<T>& operator =(CppPtr<T>&& other)
	{
		Reset();
		*this = other;
		other.Release();
		return *this;
	}

	bool operator ==(const T* ptr) const
	{
		return _ptr == ptr;
	}

	bool operator !=(const T* ptr) const
	{
		return !operator ==(ptr);
	}

	operator T*()
	{
		return _ptr;
	}

	T* operator ->()
	{
		return _ptr;
	}

	T** operator &()
	{
		return &_ptr;
	}

	T& operator *()
	{
		return *_ptr;
	}

public:
	T* Release()
	{
		T* ptr = _ptr;
		_ptr = NULL;
		return ptr;
	}

	void Reset(T* ptr = NULL)
	{
		if (_ptr != NULL)
		{
			_deleter(_ptr);
		}

		_ptr = ptr;
	}

private:
	T* _ptr;
	DELETER_FP _deleter;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_GLOBAL_HPP__
