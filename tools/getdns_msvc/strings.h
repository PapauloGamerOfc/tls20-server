/* MIT License, TLS 2.0 server contributors.
 * getdns's pinned gldns parser includes this POSIX header unconditionally.
 * The upstream generated config.h already maps strcasecmp/strncasecmp for
 * MSVC. No POSIX runtime or substitute comparison implementation is needed.
 */
#pragma once
#include <string.h>
