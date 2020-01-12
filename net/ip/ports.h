#ifndef NET_IP_PORTS_H
#define NET_IP_PORTS_H

#include <stdlib.h>
#include <netinet/in.h>

namespace net {
  namespace ip {
    // Ports.
    class ports {
      public:
        // Constructor.
        ports() = default;

        // Destructor.
        ~ports();

        // Build from string.
        bool build(const char* s);

        // Add port (host byte order).
        bool add(in_port_t port);

        // Add port range (host byte order).
        bool add(in_port_t first_port, in_port_t last_port);

        // Remove port (host byte order).
        bool remove(in_port_t port);

        // Remove port range (host byte order).
        bool remove(in_port_t first_port, in_port_t last_port);

        // Get port (host byte order).
        bool get(in_port_t port) const;

        // Print.
        void print() const;

      private:
        // Maximum number of ports.
        static constexpr const size_t max_ports = 64 * 1024;

        // Port separator.
        static constexpr const char separator = ',';

        // Ports.
        bool* _M_ports = nullptr;

        // Initialize.
        bool init();

        // Add port (host byte order).
        bool add(in_port_t port, bool val);

        // Add port range (host byte order).
        bool add(in_port_t first_port, in_port_t last_port, bool val);

        // Disable copy constructor and assignment operator.
        ports(const ports&) = delete;
        ports& operator=(const ports&) = delete;
    };

    inline ports::~ports()
    {
      if (_M_ports) {
        free(_M_ports);
      }
    }

    inline bool ports::add(in_port_t port)
    {
      return add(port, true);
    }

    inline bool ports::add(in_port_t first_port, in_port_t last_port)
    {
      return add(first_port, last_port, true);
    }

    inline bool ports::remove(in_port_t port)
    {
      return add(port, false);
    }

    inline bool ports::remove(in_port_t first_port, in_port_t last_port)
    {
      return add(first_port, last_port, false);
    }

    inline bool ports::get(in_port_t port) const
    {
      return _M_ports ? _M_ports[port] : true;
    }
  }
}

#endif // NET_IP_PORTS_H
