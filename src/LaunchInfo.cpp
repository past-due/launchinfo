//
// LaunchInfo
// Version: 1.0
//
// Copyright (c) 2020 past-due
//
// https://github.com/past-due/launchinfo
//
// Distributed under the MIT License.
// See accompanying file LICENSE or copy at https://opensource.org/licenses/MIT
//

#include "LaunchInfo.h"
#include <unordered_set>

#include "../3rdparty/whereami/whereami.h"

// should be called once, at process startup
void LaunchInfo::initialize(int argc, const char * const *argv)
{
	return getInstance()._initialize(argc, argv);
}

const LaunchInfo::ProcessDetails& LaunchInfo::getCurrentProcessDetails()
{
	return getInstance().currentProcess;
}

LaunchInfo::pid_type LaunchInfo::getParentPID()
{
	const auto& parents = getInstance().parentProcesses;
	return parents.front().pid;
}

const LaunchInfo::ImagePath& LaunchInfo::getParentImageName()
{
	const auto& parents = getInstance().parentProcesses;
	return parents.front().imageFileName;
}

const std::vector<LaunchInfo::ProcessDetails>& LaunchInfo::getAncestorProcesses()
{
	return getInstance().parentProcesses;
}

LaunchInfo& LaunchInfo::getInstance()
{
	static LaunchInfo info;
	return info;
}

#if defined(_WIN32)
LaunchInfo::ImagePath ImagePathFromPathString(const std::string& pathStr)
{
	auto lastSlashPos = pathStr.rfind('\\');
	return LaunchInfo::ImagePath(pathStr, lastSlashPos);
}
LaunchInfo::ImagePath ImagePathFromPathString(std::string&& pathStr)
{
	auto lastSlashPos = pathStr.rfind('\\');
	return LaunchInfo::ImagePath(pathStr, lastSlashPos);
}
#else
LaunchInfo::ImagePath ImagePathFromPathString(std::string&& pathStr)
{
	auto lastSlashPos = pathStr.rfind('/');
	return LaunchInfo::ImagePath(pathStr, lastSlashPos);
}
#endif

bool GetCurrentProcessPath(LaunchInfo::ImagePath& output)
{
	int dirnameLength = -1;
	int length = ::WAI_PREFIX(getExecutablePath)(NULL, 0, NULL);
	if (length < 0)
	{
		return false;
	}
	std::vector<char> utf8Buffer(length + 1, '\0');
	if (::WAI_PREFIX(getExecutablePath)(&utf8Buffer[0], length, &dirnameLength) != length)
	{
		return false;
	}
	output = LaunchInfo::ImagePath(std::string(utf8Buffer.data(), length), dirnameLength);
	return true;
}

#if defined(_WIN32)
# define WIN32_LEAN_AND_MEAN
# undef NOMINMAX
# define NOMINMAX 1
# include <windows.h>
# include <tlhelp32.h>
struct ProcessEnumInfo
{
	DWORD pid = 0;
	std::string szExeFile;
};
std::vector<ProcessEnumInfo> GetParentProcessInfo(DWORD pid)
{
	std::vector<ProcessEnumInfo> results;
	std::unordered_set<DWORD> visitedPIDs;

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		// CreateToolhelp32Snapshot failed
		return results;
	}

	// Set the size of the structure before using it.
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof( PROCESSENTRY32W );

	bool bFoundRootProcess = false;
	DWORD childPID = pid;
	do {
		ProcessEnumInfo parentProcessInfo;
		// Retrieve information about the first process,
		// and exit if unsuccessful
		if( !Process32FirstW( hProcessSnap, &pe32 ) )
		{
			// Process32FirstW failed
			CloseHandle( hProcessSnap );          // clean the snapshot object
			return results;
		}

		do
		{
			if ( pe32.th32ProcessID == childPID )
			{
				parentProcessInfo.pid = pe32.th32ParentProcessID;
				break;
			}
		} while( Process32NextW( hProcessSnap, &pe32 ) );

		if (parentProcessInfo.pid != 0 && visitedPIDs.count(parentProcessInfo.pid) == 0)
		{
			bool foundParentProcess = false;
			// Loop again to find the parent process entry
			if( !Process32FirstW( hProcessSnap, &pe32 ) )
			{
				// Unexpectedly failed calling Process32FirstW again
				CloseHandle( hProcessSnap );          // clean the snapshot object
				return results;
			}
			do
			{
				if ( pe32.th32ProcessID == parentProcessInfo.pid )
				{
					// found parent process entry
					// convert UTF-16 szExeFile to UTF-8
					std::vector<char> utf8Buffer;
					int utf8Len = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, NULL, 0, NULL, NULL);
					if ( utf8Len <= 0 )
					{
						// Encoding conversion error
						break;
					}
					utf8Buffer.resize(utf8Len, 0);
					if ( (utf8Len = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &utf8Buffer[0], utf8Len, NULL, NULL)) <= 0 )
					{
						// Encoding conversion error
						break;
					}
					parentProcessInfo.szExeFile = std::string(utf8Buffer.data(), utf8Len - 1);
					results.push_back(parentProcessInfo);
					foundParentProcess = true;
					break;
				}
			} while( Process32NextW( hProcessSnap, &pe32 ) );
			if (!foundParentProcess)
			{
				// stop searching
				break;
			}
		}
		else
		{
			if (visitedPIDs.count(parentProcessInfo.pid) > 0) { break; }
			bFoundRootProcess = true;
		}
		childPID = parentProcessInfo.pid;
		visitedPIDs.insert(parentProcessInfo.pid);
	} while (!bFoundRootProcess);

	CloseHandle( hProcessSnap );
	return results;
}

typedef BOOL (WINAPI *QueryFullProcessImageNameWFunc)(
  HANDLE hProcess,
  DWORD  dwFlags,
  LPWSTR lpExeName,
  PDWORD lpdwSize
);

#if !defined(PROCESS_NAME_NATIVE)
# define PROCESS_NAME_NATIVE	0x00000001
#endif

std::vector<LaunchInfo::ProcessDetails> GetParentProcessDetails(DWORD pid)
{
	std::vector<LaunchInfo::ProcessDetails> parentProcesses;

	std::vector<ProcessEnumInfo> parentProcessInfoList = GetParentProcessInfo(pid);
	if ( parentProcessInfoList.empty() || parentProcessInfoList.front().pid == 0 )
	{
		// Failed to get parent pid(s)
		return parentProcesses;
	}

	// Get the QueryFullProcessImageNameW function
	QueryFullProcessImageNameWFunc _QueryFullProcessImageNameW = reinterpret_cast<QueryFullProcessImageNameWFunc>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32"), "QueryFullProcessImageNameW")));

	DWORD childPID = pid;
	for (const auto& parentProcessInfo : parentProcessInfoList)
	{
		LaunchInfo::ProcessDetails parentProcess;
		parentProcess.pid = parentProcessInfo.pid;
		parentProcess.imageFileName = ImagePathFromPathString(parentProcessInfo.szExeFile); // default to parentProcessInfo.szExeFile

		HANDLE hParent = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentProcessInfo.pid );
		if ( hParent == NULL )
		{
			// OpenProcess failed
			// fall-back to the parentProcessInfo.szExeFile
			parentProcesses.push_back(parentProcess);
			continue;
		}

		FILETIME ftCreation, ftExit, ftKernel, ftUser;
		if ( GetProcessTimes(hParent, &ftCreation, &ftExit, &ftKernel, &ftUser) != 0 )
		{
			// compare with the child pid's creation time, to try to catch case where the
			// parent exits and its pid is reused before this code is executed
			HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, childPID );
			if ( hProcess != NULL )
			{
				FILETIME ftChildCreation, ftChildExit, ftChildKernel, ftChildUser;
				if ( GetProcessTimes(hParent, &ftChildCreation, &ftChildExit, &ftChildKernel, &ftChildUser) != 0 )
				{
					if ( CompareFileTime(&ftCreation, &ftChildCreation) >= 1 )
					{
						// "parent" pid's process was created after the child - detected pid reuse
						CloseHandle(hProcess);
						CloseHandle(hParent);
						// clear any parent process data - store that this child was orphaned
						parentProcess.pid = 0;
						parentProcess.imageFileName = LaunchInfo::ImagePath("<process orphaned>", std::string::npos);
						parentProcesses.push_back(parentProcess);
						// stop looking at parents
						return parentProcesses;
					}
				}
				else
				{
					// calling GetProcessTimes on the child pid unexpectedly failed
					// ignore this, for now
				}

				CloseHandle(hProcess);
			}
			else
			{
				// OpenProcess unexpectedly failed for the child pid
				// ignore this, for now
			}
		}

		if (!_QueryFullProcessImageNameW)
		{
			// QueryFullProcessImageNameW not found
			CloseHandle(hParent);
			// fall-back to the parentProcessInfo.szExeFile
			parentProcesses.push_back(parentProcess);
			continue;
		}

		// Get the parent's image file name
		const DWORD MAX_EXTENDED_WIN32_PATH = 32767;
		DWORD bufferSize = MAX_PATH + 1;
		std::vector<wchar_t> buffer;
		buffer.resize(bufferSize, static_cast<wchar_t>(0));
		BOOL bQueryResult = FALSE;
		DWORD dwError = 0;
		while ( ((bQueryResult = _QueryFullProcessImageNameW(hParent, 0, &buffer[0], &bufferSize)) == 0) && ((dwError = GetLastError()) == ERROR_INSUFFICIENT_BUFFER) && (bufferSize < MAX_EXTENDED_WIN32_PATH))
		{
			bufferSize *= 2;
			buffer.resize(bufferSize, static_cast<wchar_t>(0));
		}

		if ( bQueryResult == 0 )
		{
			// QueryFullProcessImageNameW failed in an unrecoverable way (see: dwError)
			CloseHandle(hParent);
			// fall-back to the parentProcessInfo.szExeFile
			parentProcesses.push_back(parentProcess);
			continue;
		}

		// attempt to convert the image file name to a long path
		std::vector<wchar_t> buffer_longPath;
		buffer_longPath.resize(bufferSize, static_cast<wchar_t>(0));
		DWORD dwLongPathLen = 0;
		while (((dwLongPathLen = GetLongPathNameW(buffer.data(), &buffer_longPath[0], bufferSize)) > bufferSize) && (dwLongPathLen <= MAX_EXTENDED_WIN32_PATH + 1))
		{
			// increase buffer size
			bufferSize = dwLongPathLen;
			buffer_longPath.resize(bufferSize, static_cast<wchar_t>(0));
		}
		if ( dwLongPathLen > 0 )
		{
			// succeeded at retrieving a long path - swap buffers
			buffer.swap(buffer_longPath);
		}
		else
		{
			// GetLongPathNameW failed - just use the original path
			// no-op
		}
		buffer_longPath.clear();

		// convert the UTF-16 buffer to UTF-8
		std::vector<char> utf8Buffer;
		int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, NULL, 0, NULL, NULL);
		if ( utf8Len <= 0 )
		{
			// Encoding conversion error
			CloseHandle(hParent);
			// fall-back to the parentProcessInfo.szExeFile
			parentProcesses.push_back(parentProcess);
			continue;
		}
		utf8Buffer.resize(utf8Len, 0);
		if ( (utf8Len = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, &utf8Buffer[0], utf8Len, NULL, NULL)) <= 0 )
		{
			// Encoding conversion error
			CloseHandle(hParent);
			// fall-back to the parentProcessInfo.szExeFile
			parentProcesses.push_back(parentProcess);
			continue;
		}

		CloseHandle(hParent);
		parentProcess.imageFileName = ImagePathFromPathString(std::string(utf8Buffer.data(), utf8Len - 1));

		parentProcesses.push_back(parentProcess);
		childPID = parentProcess.pid;
	}

	return parentProcesses;
}

LaunchInfo::pid_type GetCurrentProcess_PID()
{
	return GetCurrentProcessId();
}

std::vector<LaunchInfo::ProcessDetails> GetCurrentProcess_ParentDetails()
{
	return GetParentProcessDetails(GetCurrentProcessId());
}

#elif defined(__APPLE__)

# include <libproc.h>
# include <unistd.h>
# include <errno.h>

std::string GetPathFromProcessID(pid_t pid)
{
	// NOTE: This uses proc_pidpath, which is technically private API
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
	if ( ret <= 0 )
	{
		// proc_pidpath failed
		// error details can be retrieved via `strerror(errno)`
	}
	else
	{
		return std::string(pathbuf);
	}
	return "";
}

#include <sys/sysctl.h>

pid_t GetParentProcessIDForProcessID(pid_t pid)
{
    struct kinfo_proc info;
    size_t length = sizeof(struct kinfo_proc);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &info, &length, NULL, 0) < 0)
	{
        return 0;
	}
    if (length == 0)
	{
        return 0;
	}
    return info.kp_eproc.e_ppid;
}

LaunchInfo::pid_type GetCurrentProcess_PID()
{
	return getpid();
}

std::vector<LaunchInfo::ProcessDetails> GetCurrentProcess_ParentDetails()
{
	std::vector<LaunchInfo::ProcessDetails> parentProcesses;
	std::unordered_set<pid_t> visitedPIDs;

	LaunchInfo::ProcessDetails parentProcess;
	parentProcess.pid = getppid();
	while (parentProcess.pid != 0 && visitedPIDs.count(parentProcess.pid) == 0)
	{
		parentProcess.imageFileName = ImagePathFromPathString(GetPathFromProcessID(parentProcess.pid));
		parentProcesses.push_back(parentProcess);
		visitedPIDs.insert(parentProcess.pid);
		parentProcess.pid = GetParentProcessIDForProcessID(parentProcess.pid);
	}

	return parentProcesses;
}

#elif defined(__linux__) || defined(__linux) || defined(__CYGWIN__)

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sstream>
#include <iterator>
#include <algorithm>

std::string GetProcessNameFromPID(pid_t pid)
{
	char processname[BUFSIZ] = {0};
	size_t size = 0;

	// NOTE: Do not use `/proc/<pid>/comm` because it is limited in length
	std::ostringstream procCmdline;
	procCmdline << "/proc/" << pid << "/cmdline";
	FILE* f = fopen(procCmdline.str().c_str(), "r");
	if (f) {
		size = fread(processname, sizeof(char), sizeof(processname), f);
		if (size > 0)
		{
			if ('\n' == processname[size-1])
				size--;
		}
		fclose(f);
	}
	else
	{
		return "";
	}

	for (size_t i = 0; i < size; i++)
	{
		if (processname[i] == '\0')
		{
			size = i;
			break;
		}
	}

	return std::string(processname, size);
}

pid_t GetParentProcessIDForProcessID(pid_t pid)
{
	char buffer[BUFSIZ];
	std::ostringstream procStat;
	procStat << "/proc/" << pid << "/stat";
	FILE* f = fopen(procStat.str().c_str(), "r");
	if (!f)
	{
		return 0;
	}

	size_t size = fread(buffer, sizeof (char), sizeof (buffer), f);
	fclose(f);
	if (size == 0)
	{
		return 0;
	}

	// Ref: http://man7.org/linux/man-pages/man5/proc.5.html ; section: "/proc/[pid]/stat"
	// Find right-most ")" to find the end of the "(2) comm  %s" field
	char* pBufferEnd = buffer + size;
	std::reverse_iterator<char*> end(pBufferEnd);
	std::reverse_iterator<char*> begin(buffer);
	auto it_end_of_comm = std::find(end, begin, ')');
	if (it_end_of_comm == end) return 0;
	char* pBufferPos = &(*it_end_of_comm);
	pBufferPos++;
	// skip forward past space
	while (pBufferPos != pBufferEnd && *pBufferPos == ' ') { pBufferPos++; }
	if (pBufferPos == pBufferEnd) return 0;
	// (3) state  %c (skip until next whitespace)
	pBufferPos = std::find(pBufferPos, pBufferEnd, ' ');
	while (pBufferPos != pBufferEnd && *pBufferPos == ' ') { pBufferPos++; }
	if (pBufferPos == pBufferEnd) return 0;
	// (4) ppid  %d
	char *pPpidEnd = std::find(pBufferPos, pBufferEnd, ' ');
	std::string ppidStr = std::string(pBufferPos, pPpidEnd);
	try {
		return std::stoi(ppidStr);
	}
	catch (const std::exception &e) {
		return 0;
	}
}

LaunchInfo::pid_type GetCurrentProcess_PID()
{
	return getpid();
}

std::vector<LaunchInfo::ProcessDetails> GetCurrentProcess_ParentDetails()
{
	std::vector<LaunchInfo::ProcessDetails> parentProcesses;
	std::unordered_set<pid_t> visitedPIDs;

	LaunchInfo::ProcessDetails parentProcess;
	parentProcess.pid = getppid();
	while (parentProcess.pid != 0 && visitedPIDs.count(parentProcess.pid) == 0)
	{
		parentProcess.imageFileName = ImagePathFromPathString(GetProcessNameFromPID(parentProcess.pid));
		parentProcesses.push_back(parentProcess);
		visitedPIDs.insert(parentProcess.pid);
		parentProcess.pid = GetParentProcessIDForProcessID(parentProcess.pid);
	}

	return parentProcesses;
}

#else

// Not yet implemented

LaunchInfo::pid_type GetCurrentProcess_PID()
{
	// not yet implemented
	return 0;
}

std::vector<LaunchInfo::ProcessDetails> GetCurrentProcess_ParentDetails()
{
	std::vector<LaunchInfo::ProcessDetails> parentProcesses;
	// not yet implemented
	return parentProcesses;
}

#endif

bool GetCurrentProcessDetails(LaunchInfo::ProcessDetails& output)
{
	output.pid = GetCurrentProcess_PID();
	if (!GetCurrentProcessPath(output.imageFileName))
	{
		return false;
	}
	return true;
}

void LaunchInfo::_initialize(int argc, const char * const *argv)
{
	if (initialized) return;
	GetCurrentProcessDetails(currentProcess);
	parentProcesses = GetCurrentProcess_ParentDetails();
	if (parentProcesses.empty())
	{
		// ensure there's always at least one entry
		LaunchInfo::ProcessDetails unknownParent;
		unknownParent.pid = 0;
		unknownParent.imageFileName = LaunchInfo::ImagePath("<unknown>", std::string::npos);
		parentProcesses.push_back(unknownParent);
	}
	initialized = true;
}
