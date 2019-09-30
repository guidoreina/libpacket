#ifndef NET_IP_ENDPOINT_H
#define NET_IP_ENDPOINT_H

#include "net/ip/address.h"

namespace net {
  namespace ip {
    // Endpoint (IP address + port).
    class endpoint {
      public:
        // Constructor.
        endpoint() = default;
        endpoint(uint32_t addr, in_port_t port);
        endpoint(struct in_addr addr, in_port_t port);
        endpoint(const struct in6_addr& addr, in_port_t port);
        endpoint(const class address& addr, in_port_t port);
        endpoint(const endpoint& ep) = default;

        // Destructor.
        ~endpoint() = default;

        // Assignment operator.
        endpoint& operator=(const endpoint& ep) = default;

        // Assign.
        void assign(uint32_t addr, in_port_t port);
        void assign(struct in_addr addr, in_port_t port);
        void assign(const struct in6_addr& addr, in_port_t port);
        void assign(const class address& addr, in_port_t port);

        // Equal operator.
        bool operator==(const endpoint& ep) const;

        // Get address.
        const class address& address() const;

        // Get port.
        in_port_t port() const;

        // To string.
        const char* to_string(char* s, size_t size) const;

      private:
        // Address.
        class address _M_address;

        // Port.
        in_port_t _M_port;
    };

    inline endpoint::endpoint(uint32_t addr, in_port_t port)
      : _M_address(addr),
        _M_port(port)
    {
    }

    inline endpoint::endpoint(struct in_addr addr, in_port_t port)
      : _M_address(addr),
        _M_port(port)
    {
    }

    inline endpoint::endpoint(const struct in6_addr& addr, in_port_t port)
      : _M_address(addr),
        _M_port(port)
    {
    }

    inline endpoint::endpoint(const class address& addr, in_port_t port)
      : _M_address(addr),
        _M_port(port)
    {
    }

    inline void endpoint::assign(uint32_t addr, in_port_t port)
    {
      _M_address = addr;
      _M_port = port;
    }

    inline void endpoint::assign(struct in_addr addr, in_port_t port)
    {
      _M_address = addr;
      _M_port = port;
    }

    inline void endpoint::assign(const struct in6_addr& addr, in_port_t port)
    {
      _M_address = addr;
      _M_port = port;
    }

    inline void endpoint::assign(const class address& addr, in_port_t port)
    {
      _M_address = addr;
      _M_port = port;
    }

    inline bool endpoint::operator==(const endpoint& ep) const
    {
      return ((_M_port == ep._M_port) && (_M_address == ep._M_address));
    }

    inline const class address& endpoint::address() const
    {
      return _M_address;
    }

    inline in_port_t endpoint::port() const
    {
      return _M_port;
    }
  }
}

#endif // NET_IP_ENDPOINT_H
