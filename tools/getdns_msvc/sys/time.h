/* MIT License, TLS 2.0 server contributors.
 * MSVC has timeval in Winsock. getdns supplies its own gettimeofday shim and
 * includes its generated config.h before this compatibility header.
 */
#pragma once
#include <winsock2.h>
#include <time.h>
