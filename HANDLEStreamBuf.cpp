#if defined(_WINDOWS) && defined(_M_AMD64) && !defined(_AMD64_)
# define _AMD64_
#endif

#include <FileApi.h>
#include <ErrHandlingApi.h>

#include <string>
#include <stdexcept>
#include "HANDLEStreamBuf.hpp"

using std::to_string;
using std::runtime_error;

HANDLEStreamBuf::HANDLEStreamBuf(HANDLE hFileHandle)
	: hFileHandle(hFileHandle), buffer(new char[16 * 1024])
{
	setg(buffer.get(), buffer.get() + 16 * 1024, buffer.get() + 16 * 1024);
	underflow();
}

int HANDLEStreamBuf::underflow()
{
	if (endOfFile)
		return traits_type::eof();

	if (gptr() >= egptr())
	{
		DWORD dwReadCount = 0u;

		if (::ReadFile(hFileHandle, eback(), egptr() - eback(), &dwReadCount, NULL))
		{
			if (dwReadCount)
			{
				setg(eback(), eback(), eback() + dwReadCount);
				return *gptr();
			}

			endOfFile = true;
			return traits_type::eof();
		}
		else
			throw runtime_error("Error reading from OS native file HANDLE: " + to_string(::GetLastError()));
	}

	return *gptr();
}
