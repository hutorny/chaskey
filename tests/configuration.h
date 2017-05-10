#pragma once
#include "miculog.ccs"
struct TestLog;
struct LogAppender {
	static void log(miculog::level, const char* fmt, ...) noexcept
								__attribute__ ((format (printf, 2, 3)));
};
namespace miculog {
template<typename Build> struct ClassLogLevels<TestLog, Build> :
	Levels<level::info, level::warn, level::error, level::fail> {};

template<typename Build>
struct appender<TestLog,Build>: public LogAppender {};
}
