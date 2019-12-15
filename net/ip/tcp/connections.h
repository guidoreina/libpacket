#ifndef NET_IP_TCP_CONNECTIONS_H
#define NET_IP_TCP_CONNECTIONS_H

#include <stdlib.h>
#include "net/ip/tcp/connection.h"

namespace net {
  namespace ip {
    namespace tcp {
      // Connection hash table.
      class connections {
        public:
          // Minimum size of the hash table (256).
          static constexpr const size_t min_size = static_cast<size_t>(1) << 8;

          // Maximum size of the hash table (4294967296 [64bit], 65536 [32bit]).
          static constexpr const size_t
                 max_size = static_cast<size_t>(1) << (4 * sizeof(size_t));

          // Default size of the hash table (4096).
          static constexpr const size_t
                 default_size = static_cast<size_t>(1) << 12;

          // Minimum number of connections.
          static constexpr const size_t min_connections = min_size;

          // Maximum number of connections.
          static constexpr const size_t max_connections = max_size;

          // Maximum number of connections (default) (1048576).
          static constexpr const size_t
                 default_max_connections = static_cast<size_t>(1) << 20;

          // Minimum connection timeout (seconds).
          static constexpr const uint64_t min_timeout = 5;

          // Default connection timeout (seconds).
          static constexpr const uint64_t default_timeout = 2 * 3600;

          // Minimum TCP time wait (seconds).
          static constexpr const uint64_t min_time_wait = 1;

          // Default TCP time wait (seconds).
          static constexpr const uint64_t default_time_wait = 2 * 60;

          // Constructor.
          connections() = default;

          // Destructor.
          ~connections();

          // Clear.
          void clear();

          // Initialize.
          bool init(size_t size = default_size,
                    size_t maxconns = default_max_connections,
                    uint64_t timeout = default_timeout,
                    uint64_t time_wait = default_time_wait);

          // Process TCP segment.
          const connection* process(const iphdr* iphdr,
                                    const tcphdr* tcphdr,
                                    uint64_t now);

          const connection* process(const iphdr* iphdr,
                                    const tcphdr* tcphdr,
                                    uint64_t now,
                                    direction& dir);

          const connection* process(const ip6_hdr* iphdr,
                                    const tcphdr* tcphdr,
                                    uint64_t now);

          const connection* process(const ip6_hdr* iphdr,
                                    const tcphdr* tcphdr,
                                    uint64_t now,
                                    direction& dir);

          // Remove expired connections.
          void remove_expired(uint64_t now);

        private:
          static constexpr const size_t connection_allocation = 1024;

          // Connection stack.
          class stack {
            public:
              // Constructor.
              stack() = default;

              // Destructor.
              ~stack();

              // Clear.
              void clear();

              // Push connection.
              bool push(connection* conn);

              // Pop connection.
              connection* pop();

              // Get connection.
              const connection* get(size_t idx) const;
              connection* get(size_t idx);

              // Get connections.
              connection** get();

              // Get number of connections.
              size_t count() const;

              // Set number of connections.
              void count(size_t n);

              // Is the stack empty?
              bool empty() const;

            private:
              connection** _M_conns = nullptr;
              size_t _M_size = 0;
              size_t _M_used = 0;

              // Disable copy constructor and assignment operator.
              stack(const stack&) = delete;
              stack& operator=(const stack&) = delete;
          };

          // Connection hash table.
          stack* _M_conns = nullptr;

          // Size of the hash table.
          size_t _M_size = 0;

          // Mask (for performing modulo).
          size_t _M_mask;

          // Maximum number of connections.
          size_t _M_max_connections;

          // Number of connections.
          size_t _M_nconns = 0;

          // Free connections.
          stack _M_free;

          // Connection timeout.
          uint64_t _M_timeout;

          // Time wait.
          uint64_t _M_time_wait;

          // Next connection id.
          size_t _M_connid = 0;

          // Get free connection.
          connection* get_free_connection();

          // Allocate connections.
          bool allocate_connections(size_t count = connection_allocation);

          // Remove connection.
          void remove(connection* conn);

          // Process TCP segment.
          template<typename IpHeader>
          const connection* process_(const IpHeader* iphdr,
                                     const tcphdr* tcphdr,
                                     uint64_t now,
                                     direction& dir);

          // Disable copy constructor and assignment operator.
          connections(const connections&) = delete;
          connections& operator=(const connections&) = delete;
      };

      inline connections::~connections()
      {
        clear();
      }

      const connection* tcp::connections::process(const iphdr* iphdr,
                                                  const tcphdr* tcphdr,
                                                  uint64_t now)
      {
        direction dir;
        return process_(iphdr, tcphdr, now, dir);
      }

      const connection* tcp::connections::process(const iphdr* iphdr,
                                                  const tcphdr* tcphdr,
                                                  uint64_t now,
                                                  direction& dir)
      {
        return process_(iphdr, tcphdr, now, dir);
      }

      const connection* tcp::connections::process(const ip6_hdr* iphdr,
                                                  const tcphdr* tcphdr,
                                                  uint64_t now)
      {
        direction dir;
        return process_(iphdr, tcphdr, now, dir);
      }

      const connection* tcp::connections::process(const ip6_hdr* iphdr,
                                                  const tcphdr* tcphdr,
                                                  uint64_t now,
                                                  direction& dir)
      {
        return process_(iphdr, tcphdr, now, dir);
      }

      inline connections::stack::~stack()
      {
        clear();
      }

      inline connection* connections::stack::pop()
      {
        return (_M_used > 0) ? _M_conns[--_M_used] : nullptr;
      }

      inline const connection* connections::stack::get(size_t idx) const
      {
        return (idx < _M_used) ? _M_conns[idx] : nullptr;
      }

      inline connection* connections::stack::get(size_t idx)
      {
        return (idx < _M_used) ? _M_conns[idx] : nullptr;
      }

      inline connection** connections::stack::get()
      {
        return _M_conns;
      }

      inline size_t connections::stack::count() const
      {
        return _M_used;
      }

      inline void connections::stack::count(size_t n)
      {
        _M_used = n;
      }

      inline bool connections::stack::empty() const
      {
        return (_M_used == 0);
      }

      inline connection* connections::get_free_connection()
      {
        connection* conn = _M_free.pop();
        return conn ? conn : allocate_connections() ? _M_free.pop() : nullptr;
      }

      inline void connections::remove(connection* conn)
      {
        if (!_M_free.push(conn)) {
          free(conn);
        }

        _M_nconns--;
      }
    }
  }
}

#endif // NET_IP_TCP_CONNECTIONS_H
