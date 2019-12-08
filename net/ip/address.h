#ifndef NET_IP_ADDRESS_H
#define NET_IP_ADDRESS_H

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util/hash.h"

namespace net {
  namespace ip {
    // IP address (either an IPv4 address or an IPv6 address).
    class address {
      public:
        // Constructor.
        address() = default;
        address(uint32_t addr);
        address(struct in_addr addr);
        address(const struct in6_addr& addr);
        address(const address& addr) = default;

        // Destructor.
        ~address() = default;

        // Assignment operator.
        address& operator=(uint32_t addr);
        address& operator=(struct in_addr addr);
        address& operator=(const struct in6_addr& addr);
        address& operator=(const address& addr) = default;

        // Equal operator.
        bool operator==(uint32_t addr) const;
        bool operator==(struct in_addr addr) const;
        bool operator==(const struct in6_addr& addr) const;
        bool operator==(const address& addr) const;

        // To string.
        const char* to_string(char* s, size_t size) const;

        // Get address family.
        int address_family() const;

        // Compute hash.
        uint32_t hash() const;
        static uint32_t hash(uint32_t addr);
        static uint32_t hash(struct in_addr addr);
        static uint32_t hash(const struct in6_addr& addr);

      private:
        // Address family (either AF_INET or AF_INET6).
        int _M_address_family;

        // Address.
        uint32_t _M_address[4];
    };

    inline address::address(uint32_t addr)
      : _M_address_family(AF_INET)
    {
      _M_address[0] = addr;
      _M_address[1] = 0;
      _M_address[2] = 0;
      _M_address[3] = 0;
    }

    inline address::address(struct in_addr addr)
      : _M_address_family(AF_INET)
    {
      _M_address[0] = addr.s_addr;
      _M_address[1] = 0;
      _M_address[2] = 0;
      _M_address[3] = 0;
    }

    inline address::address(const struct in6_addr& addr)
      : _M_address_family(AF_INET6)
    {
      _M_address[0] = addr.s6_addr32[0];
      _M_address[1] = addr.s6_addr32[1];
      _M_address[2] = addr.s6_addr32[2];
      _M_address[3] = addr.s6_addr32[3];
    }

    inline address& address::operator=(uint32_t addr)
    {
      _M_address_family = AF_INET;

      _M_address[0] = addr;
      _M_address[1] = 0;
      _M_address[2] = 0;
      _M_address[3] = 0;

      return *this;
    }

    inline address& address::operator=(struct in_addr addr)
    {
      _M_address_family = AF_INET;

      _M_address[0] = addr.s_addr;
      _M_address[1] = 0;
      _M_address[2] = 0;
      _M_address[3] = 0;

      return *this;
    }

    inline address& address::operator=(const struct in6_addr& addr)
    {
      _M_address_family = AF_INET6;

      _M_address[0] = addr.s6_addr32[0];
      _M_address[1] = addr.s6_addr32[1];
      _M_address[2] = addr.s6_addr32[2];
      _M_address[3] = addr.s6_addr32[3];

      return *this;
    }

    inline bool address::operator==(uint32_t addr) const
    {
      return ((_M_address_family == AF_INET) && (_M_address[0] == addr));
    }

    inline bool address::operator==(struct in_addr addr) const
    {
      return ((_M_address_family == AF_INET) && (_M_address[0] == addr.s_addr));
    }

    inline bool address::operator==(const struct in6_addr& addr) const
    {
      return ((_M_address_family == AF_INET6) &&
              (((_M_address[0] ^ addr.s6_addr32[0]) |
                (_M_address[1] ^ addr.s6_addr32[1]) |
                (_M_address[2] ^ addr.s6_addr32[2]) |
                (_M_address[3] ^ addr.s6_addr32[3])) == 0));
    }

    inline bool address::operator==(const address& addr) const
    {
      return ((_M_address_family == addr._M_address_family) &&
              (((_M_address[0] ^ addr._M_address[0]) |
                (_M_address[1] ^ addr._M_address[1]) |
                (_M_address[2] ^ addr._M_address[2]) |
                (_M_address[3] ^ addr._M_address[3])) == 0));
    }

    inline const char* address::to_string(char* s, size_t size) const
    {
      return inet_ntop(_M_address_family, _M_address, s, size);
    }

    inline int address::address_family() const
    {
      return _M_address_family;
    }

    inline uint32_t address::hash() const
    {
      static constexpr const uint32_t initval = 0;

      return (_M_address_family == AF_INET) ?
               _M_address[0] :
               util::hash::hash_3words(_M_address[0] ^ _M_address[1],
                                       _M_address[2],
                                       _M_address[3],
                                       initval);
    }

    inline uint32_t address::hash(uint32_t addr)
    {
      return addr;
    }

    inline uint32_t address::hash(struct in_addr addr)
    {
      return addr.s_addr;
    }

    inline uint32_t address::hash(const struct in6_addr& addr)
    {
      static constexpr const uint32_t initval = 0;

      return util::hash::hash_3words(addr.s6_addr32[0] ^ addr.s6_addr32[1],
                                     addr.s6_addr32[2],
                                     addr.s6_addr32[3],
                                     initval);
    }
  }
}

#endif // NET_IP_ADDRESS_H
