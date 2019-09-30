#include <string.h>
#include <stdio.h>
#include "net/ip/endpoint.h"

const char* net::ip::endpoint::to_string(char* s, size_t size) const
{
  // IPv4?
  if (_M_address.address_family() == AF_INET) {
    if (_M_address.to_string(s, size)) {
      const size_t len = strlen(s);
      const size_t left = size - len;
      if (snprintf(s + len, left, ":%u", _M_port) <
          static_cast<int>(left)) {
        return s;
      }
    }
  } else {
    if (_M_address.to_string(s + 1, size - 2)) {
      const size_t len = 1 + strlen(s + 1);
      const size_t left = size - len;
      if (snprintf(s + len, left, "]:%u", _M_port) <
          static_cast<int>(left)) {
        *s = '[';
        return s;
      }
    }
  }

  return nullptr;
}
