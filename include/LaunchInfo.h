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

#pragma once

#ifndef __INCLUDED_LAUNCH_INFO_H__
#define __INCLUDED_LAUNCH_INFO_H__

#include <string>
#include <vector>

#if defined(_WIN32)
# include <cstdint> // for uint32_t
#elif defined(__APPLE__)
# include <unistd.h> // for pid_t
#elif defined(__linux__) || defined(__linux) || defined(__CYGWIN__)
# include <sys/types.h> // for pid_t
#endif

class LaunchInfo
{
public:
#if defined(_WIN32)
	typedef uint32_t pid_type;
#elif defined(__APPLE__)
	typedef pid_t pid_type;
#elif defined(__linux__) || defined(__linux) || defined(__CYGWIN__)
	typedef pid_t pid_type;
#else
	typedef int pid_type;
#endif

	struct ProcessDetails
	{
		ProcessDetails() {}
		ProcessDetails(pid_type pid, const std::string imageFileName) { }
		pid_type pid = 0;
		std::string imageFileName;
	};

public:

	// should be called once, at process startup
	static void initialize(int argc, const char * const *argv);

	static pid_type getParentPID();
	static const std::string& getParentImageName();
	static const std::vector<ProcessDetails>& getAncestorProcesses();

private:
	static LaunchInfo& getInstance();
	void _initialize(int argc, const char * const *argv);
private:
	bool initialized = false;
	std::vector<ProcessDetails> parentProcesses = {ProcessDetails(0, "<not initialized>")};
};

#endif // __INCLUDED_LAUNCH_INFO_H__
