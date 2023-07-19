#pragma once

#ifdef WIN32
#include <WinSock2.h>
#include <io.h>
#else
#include <netinet/in.h>
#endif

#include <event2/event.h>
#include <fmt/format.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
