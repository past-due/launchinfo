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

	class ImagePath
	{
	public:
		ImagePath() { }
		ImagePath(const std::string& fullPath, size_t dirnameLength)
		: m_fullPath(fullPath)
		, m_dirnameLength(dirnameLength)
		{ }
		ImagePath(std::string&& fullPath, size_t dirnameLength)
		: m_fullPath(fullPath)
		, m_dirnameLength(dirnameLength)
		{ }

	public:
		inline const std::string& fullPath() const { return m_fullPath; }
		inline std::string dirname() const { return (m_dirnameLength != std::string::npos) ? m_fullPath.substr(0, m_dirnameLength) : ""; }
		inline std::string basename() const { return (m_dirnameLength != std::string::npos) ? m_fullPath.substr(m_dirnameLength + 1) : m_fullPath; }

	private:
		std::string m_fullPath;
		size_t m_dirnameLength = std::string::npos;
	};

	struct ProcessDetails
	{
		ProcessDetails() {}
		ProcessDetails(pid_type pid, LaunchInfo::ImagePath&& imageFileName)
		: pid(pid)
		, imageFileName(std::move(imageFileName))
		{ }
		pid_type pid = 0;
		LaunchInfo::ImagePath imageFileName;
	};

public:

	// should be called once, at process startup
	static void initialize(int argc, const char * const *argv);

	static const ProcessDetails& getCurrentProcessDetails();
	static pid_type getParentPID();
	static const ImagePath& getParentImageName();
	static const std::vector<ProcessDetails>& getAncestorProcesses();

private:
	static LaunchInfo& getInstance();
	void _initialize(int argc, const char * const *argv);
private:
	bool initialized = false;
	ProcessDetails currentProcess = {ProcessDetails(0, ImagePath("<not initialized>", std::string::npos))};
	std::vector<ProcessDetails> parentProcesses = {ProcessDetails(0, ImagePath("<not initialized>", std::string::npos))};
};

#endif // __INCLUDED_LAUNCH_INFO_H__
