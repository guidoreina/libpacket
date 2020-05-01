#ifndef NET_IP_ADDRESS_LIST_H
#define NET_IP_ADDRESS_LIST_H

#include <stdlib.h>
#include <netinet/in.h>
#include "string/buffer.h"

namespace net {
  namespace ip {
    // IP addresses (either IPv4 or IPv6 addresses).
    class address_list {
      public:
        // Default separator for the string representation of the list.
        static constexpr const char default_separator = '|';

        // Constructor.
        address_list(char separator = default_separator);

        // Destructor.
        ~address_list() = default;

        // Clear.
        void clear();

        // Insert IPv4 address.
        bool insert(uint32_t addr);
        bool insert(struct in_addr addr);

        // Insert IPv6 address.
        bool insert(const struct in6_addr& addr);

        // Get count.
        size_t count() const;

        // Empty?
        bool empty() const;

        // To string.
        const char* to_string() const;
        const char* to_string(size_t& len) const;

      private:
        // Buffer for the string representation of the list.
        mutable string::buffer _M_buf;

        // Separator for the string representation of the list.
        const char _M_separator;

        // IPv4 addresses.
        class ipv4_addresses {
          public:
            // Constructor.
            ipv4_addresses() = default;

            // Destructor.
            ~ipv4_addresses();

            // Clear.
            void clear();

            // Insert IPv4 address.
            bool insert(uint32_t addr);

            // Get count.
            size_t count() const;

            // Empty?
            bool empty() const;

            // To string.
            bool to_string(char separator, string::buffer& buf) const;

          private:
            // Allocation.
            static constexpr const size_t allocation = 32;

            uint32_t* _M_addresses = nullptr;
            size_t _M_size = 0;
            size_t _M_used = 0;

            // Allocate.
            bool allocate();

            // Disable copy constructor and assignment operator.
            ipv4_addresses(const ipv4_addresses&) = delete;
            ipv4_addresses& operator=(const ipv4_addresses&) = delete;
        };

        ipv4_addresses _M_ipv4;

        // IPv6 addresses.
        class ipv6_addresses {
          public:
            // Constructor.
            ipv6_addresses() = default;

            // Destructor.
            ~ipv6_addresses();

            // Clear.
            void clear();

            // Insert IPv6 address.
            bool insert(const struct in6_addr& addr);

            // Get count.
            size_t count() const;

            // Empty?
            bool empty() const;

            // To string.
            bool to_string(char separator, string::buffer& buf) const;

          private:
            // Allocation.
            static constexpr const size_t allocation = 32;

            struct in6_addr* _M_addresses = nullptr;
            size_t _M_size = 0;
            size_t _M_used = 0;

            // Allocate.
            bool allocate();

            // Same IPv6 address?
            static bool equal(const struct in6_addr& addr1,
                              const struct in6_addr& addr2);

            // Disable copy constructor and assignment operator.
            ipv6_addresses(const ipv6_addresses&) = delete;
            ipv6_addresses& operator=(const ipv6_addresses&) = delete;
        };

        ipv6_addresses _M_ipv6;

        // Disable copy constructor and assignment operator.
        address_list(const address_list&) = delete;
        address_list& operator=(const address_list&) = delete;
    };

    inline address_list::address_list(char separator)
      : _M_separator(separator)
    {
    }

    inline void address_list::clear()
    {
      _M_ipv4.clear();
      _M_ipv6.clear();
    }

    inline bool address_list::insert(uint32_t addr)
    {
      return _M_ipv4.insert(addr);
    }

    inline bool address_list::insert(struct in_addr addr)
    {
      return _M_ipv4.insert(addr.s_addr);
    }

    inline bool address_list::insert(const struct in6_addr& addr)
    {
      return _M_ipv6.insert(addr);
    }

    inline size_t address_list::count() const
    {
      return _M_ipv4.count() + _M_ipv6.count();
    }

    inline bool address_list::empty() const
    {
      return ((_M_ipv4.empty()) && (_M_ipv6.empty()));
    }

    inline const char* address_list::to_string() const
    {
      size_t len;
      return to_string(len);
    }

    inline address_list::ipv4_addresses::~ipv4_addresses()
    {
      if (_M_addresses) {
        free(_M_addresses);
      }
    }

    inline void address_list::ipv4_addresses::clear()
    {
      _M_used = 0;
    }

    inline size_t address_list::ipv4_addresses::count() const
    {
      return _M_used;
    }

    inline bool address_list::ipv4_addresses::empty() const
    {
      return (_M_used == 0);
    }

    inline address_list::ipv6_addresses::~ipv6_addresses()
    {
      if (_M_addresses) {
        free(_M_addresses);
      }
    }

    inline void address_list::ipv6_addresses::clear()
    {
      _M_used = 0;
    }

    inline size_t address_list::ipv6_addresses::count() const
    {
      return _M_used;
    }

    inline bool address_list::ipv6_addresses::empty() const
    {
      return (_M_used == 0);
    }

    inline
    bool address_list::ipv6_addresses::equal(const struct in6_addr& addr1,
                                             const struct in6_addr& addr2)
    {
      return (((addr1.s6_addr32[0] ^ addr2.s6_addr32[0]) |
               (addr1.s6_addr32[1] ^ addr2.s6_addr32[1]) |
               (addr1.s6_addr32[2] ^ addr2.s6_addr32[2]) |
               (addr1.s6_addr32[3] ^ addr2.s6_addr32[3])) == 0);
    }
  }
}

#endif // NET_IP_ADDRESS_LIST_H
