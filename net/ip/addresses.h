#ifndef NET_IP_ADDRESSES_H
#define NET_IP_ADDRESSES_H

#include <netinet/in.h>
#include "util/trie.h"

namespace net {
  namespace ip {
    // IP addresses (either IPv4 or IPv6 addresses).
    template<typename Value>
    class addresses {
      public:
        typedef Value value_type;

        // Constructor.
        addresses() = default;

        // Destructor.
        ~addresses() = default;

        // Insert IPv4 address.
        bool insert(uint32_t addr, const value_type& val);
        bool insert(struct in_addr addr, const value_type& val);
        bool insert(uint32_t addr, size_t prefixlen, const value_type& val);

        // Insert IPv6 address.
        bool insert(const struct in6_addr& addr, const value_type& val);
        bool insert(const struct in6_addr& addr,
                    size_t prefixlen,
                    const value_type& val);

        // Find IP address.
        const value_type* find(uint32_t addr) const;
        const value_type* find(struct in_addr addr) const;
        const value_type* find(const struct in6_addr& addr) const;

      private:
        // IPv4 addresses.
        util::trie<value_type> _M_ipv4;

        // IPv6 addresses.
        util::trie<value_type> _M_ipv6;

        // Disable copy constructor and assignment operator.
        addresses(const addresses&) = delete;
        addresses& operator=(const addresses&) = delete;
    };

    template<typename Value>
    inline bool addresses<Value>::insert(uint32_t addr, const value_type& val)
    {
      return _M_ipv4.insert(&addr, 32, val);
    }

    template<typename Value>
    inline bool addresses<Value>::insert(struct in_addr addr,
                                         const value_type& val)
    {
      return _M_ipv4.insert(&addr.s_addr, 32, val);
    }

    template<typename Value>
    inline bool addresses<Value>::insert(uint32_t addr,
                                         size_t prefixlen,
                                         const value_type& val)
    {
      return _M_ipv4.insert(&addr, prefixlen, val);
    }

    template<typename Value>
    inline bool addresses<Value>::insert(const struct in6_addr& addr,
                                         const value_type& val)
    {
      return _M_ipv6.insert(&addr, 128, val);
    }

    template<typename Value>
    inline bool addresses<Value>::insert(const struct in6_addr& addr,
                                         size_t prefixlen,
                                         const value_type& val)
    {
      return _M_ipv6.insert(&addr, prefixlen, val);
    }

    template<typename Value>
    inline const typename addresses<Value>::value_type*
    addresses<Value>::find(uint32_t addr) const
    {
      return _M_ipv4.find(&addr, 32);
    }

    template<typename Value>
    inline const typename addresses<Value>::value_type*
    addresses<Value>::find(struct in_addr addr) const
    {
      return _M_ipv4.find(&addr.s_addr, 32);
    }

    template<typename Value>
    inline const typename addresses<Value>::value_type*
    addresses<Value>::find(const struct in6_addr& addr) const
    {
      return _M_ipv6.find(&addr, 128);
    }
  }
}

#endif // NET_IP_ADDRESSES_H
