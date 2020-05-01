#include <arpa/inet.h>
#include "net/ip/address_list.h"

const char* net::ip::address_list::to_string(size_t& len) const
{
  // Clear buffer.
  _M_buf.clear();

  // If there are IPv4 addresses...
  if (!_M_ipv4.empty()) {
    if (_M_ipv4.to_string(_M_separator, _M_buf)) {
      if (!_M_ipv6.empty()) {
        if ((_M_buf.push_back(_M_separator)) &&
            (_M_ipv6.to_string(_M_separator, _M_buf)) &&
            (_M_buf.push_back(0))) {
          len = _M_buf.length() - 1;
          return static_cast<const char*>(_M_buf.data());
        }
      } else if (_M_buf.push_back(0)) {
        len = _M_buf.length() - 1;
        return static_cast<const char*>(_M_buf.data());
      }
    }
  } else {
    if (!_M_ipv6.empty()) {
      if ((_M_ipv6.to_string(_M_separator, _M_buf)) &&
          (_M_buf.push_back(0))) {
        len = _M_buf.length() - 1;
        return static_cast<const char*>(_M_buf.data());
      }
    } else {
      len = 0;
      return "";
    }
  }

  return nullptr;
}

bool net::ip::address_list::ipv4_addresses::insert(uint32_t addr)
{
  // Search IPv4 address.
  for (size_t i = _M_used; i > 0; i--) {
    if (_M_addresses[i - 1] == addr) {
      return true;
    }
  }

  if (allocate()) {
    _M_addresses[_M_used++] = addr;

    return true;
  }

  return false;
}

bool net::ip::address_list::ipv4_addresses::to_string(char separator,
                                                      string::buffer& buf) const
{
  for (size_t i = 0; i < _M_used; i++) {
    char ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &_M_addresses[i], ip, sizeof(ip))) {
      if (i > 0) {
        if (!buf.push_back(separator)) {
          return false;
        }
      }

      if (!buf.append(ip, strlen(ip))) {
        return false;
      }
    }
  }

  return true;
}

bool net::ip::address_list::ipv4_addresses::allocate()
{
  if (_M_used < _M_size) {
    return true;
  } else {
    const size_t size = (_M_size > 0) ? _M_size * 2 : allocation;

    uint32_t* addresses = static_cast<uint32_t*>(
                            realloc(_M_addresses, size * sizeof(uint32_t))
                          );

    if (addresses) {
      _M_addresses = addresses;
      _M_size = size;

      return true;
    } else {
      return false;
    }
  }
}

bool net::ip::address_list::ipv6_addresses::insert(const struct in6_addr& addr)
{
  // Search IPv6 address.
  for (size_t i = _M_used; i > 0; i--) {
    if (equal(_M_addresses[i - 1], addr)) {
      return true;
    }
  }

  if (allocate()) {
    _M_addresses[_M_used++] = addr;

    return true;
  }

  return false;
}

bool net::ip::address_list::ipv6_addresses::to_string(char separator,
                                                      string::buffer& buf) const
{
  for (size_t i = 0; i < _M_used; i++) {
    char ip[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &_M_addresses[i], ip, sizeof(ip))) {
      if (i > 0) {
        if (!buf.push_back(separator)) {
          return false;
        }
      }

      if (!buf.append(ip, strlen(ip))) {
        return false;
      }
    }
  }

  return true;
}

bool net::ip::address_list::ipv6_addresses::allocate()
{
  if (_M_used < _M_size) {
    return true;
  } else {
    const size_t size = (_M_size > 0) ? _M_size * 2 : allocation;

    struct in6_addr*
      addresses = static_cast<struct in6_addr*>(
                    realloc(_M_addresses, size * sizeof(struct in6_addr))
                  );

    if (addresses) {
      _M_addresses = addresses;
      _M_size = size;

      return true;
    } else {
      return false;
    }
  }
}
