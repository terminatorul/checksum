#if defined(_WINDOWS) && defined(_M_AMD64) && !defined(_AMD64_)
# define _AMD64_
#endif

#include <fileapi.h>
#include <streambuf>
#include <memory>

class HANDLEStreamBuf: public std::streambuf
{
protected:
	HANDLE hFileHandle;
	bool endOfFile = false;
	std::unique_ptr<char []> buffer;

	int underflow();

public:
	HANDLEStreamBuf(HANDLE hFileHandle);
	HANDLEStreamBuf(HANDLEStreamBuf const &other) = delete;
	HANDLEStreamBuf(HANDLEStreamBuf &&other) = default;

	HANDLEStreamBuf &operator =(HANDLEStreamBuf const &other) = delete;
	HANDLEStreamBuf &operator =(HANDLEStreamBuf &&other) = default;
};
