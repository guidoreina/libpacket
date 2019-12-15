#ifndef NET_IP_TCP_CONNECTION_H
#define NET_IP_TCP_CONNECTION_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include "net/ip/endpoint.h"
#include "net/ip/tcp/direction.h"

namespace net {
  namespace ip {
    namespace tcp {
      // TCP connection.
      class connection {
        public:
          // TCP time wait.
          static uint64_t time_wait;

          // Connection state:
          // http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf
          enum class state {
            connection_requested,
            connection_established,
            data_transfer,
            closing,
            closed,
            failure
          };

          // Constructor.
          connection() = default;
          connection(const struct iphdr* iphdr,
                     const struct tcphdr* tcphdr,
                     enum state s,
                     uint64_t timestamp);

          connection(const struct ip6_hdr* iphdr,
                     const struct tcphdr* tcphdr,
                     enum state s,
                     uint64_t timestamp);

          // Destructor.
          ~connection() = default;

          // Assign.
          void assign(const struct iphdr* iphdr,
                      const struct tcphdr* tcphdr,
                      enum state s,
                      uint64_t timestamp);

          void assign(const struct ip6_hdr* iphdr,
                      const struct tcphdr* tcphdr,
                      enum state s,
                      uint64_t timestamp);

          // Equal operator.
          bool operator==(const connection& conn) const;

          // Match?
          bool match(const struct iphdr* iphdr,
                     const struct tcphdr* tcphdr) const;

          bool match(const struct iphdr* iphdr,
                     const struct tcphdr* tcphdr,
                     direction& dir) const;

          bool match(const struct ip6_hdr* iphdr,
                     const struct tcphdr* tcphdr) const;

          bool match(const struct ip6_hdr* iphdr,
                     const struct tcphdr* tcphdr,
                     direction& dir) const;

          // Process packet.
          bool process(direction dir, uint8_t flags, uint64_t timestamp);

          // Get client.
          const endpoint& client() const;

          // Get server.
          const endpoint& server() const;

          // Get connection state.
          enum state state() const;

          // Set connection state.
          void state(enum state s);

          // Get creation timestamp.
          uint64_t creation_timestamp() const;

          // Get timestamp of the last packet.
          uint64_t last_timestamp() const;

          // Touch connection.
          void touch(uint64_t timestamp);

        private:
          // Client.
          endpoint _M_client;

          // Server.
          endpoint _M_server;

          // Connection state.
          enum state _M_state;

          // Who initiates the connection shutdown?
          originator _M_active_closer;

          // Timestamp.
          struct {
            uint64_t creation;
            uint64_t last_packet;
          } _M_timestamp;

          // Disable copy constructor and assignment operator.
          connection(const connection&) = delete;
          connection& operator=(const connection&) = delete;
      };

      inline connection::connection(const struct iphdr* iphdr,
                                    const struct tcphdr* tcphdr,
                                    enum state s,
                                    uint64_t timestamp)
        : _M_client(iphdr->saddr, ntohs(tcphdr->source)),
          _M_server(iphdr->daddr, ntohs(tcphdr->dest)),
          _M_state(s),
          _M_timestamp{timestamp}
      {
      }

      inline connection::connection(const struct ip6_hdr* iphdr,
                                    const struct tcphdr* tcphdr,
                                    enum state s,
                                    uint64_t timestamp)
        : _M_client(iphdr->ip6_src, ntohs(tcphdr->source)),
          _M_server(iphdr->ip6_dst, ntohs(tcphdr->dest)),
          _M_state(s),
          _M_timestamp{timestamp}
      {
      }

      inline void connection::assign(const struct iphdr* iphdr,
                                     const struct tcphdr* tcphdr,
                                     enum state s,
                                     uint64_t timestamp)
      {
        _M_client.assign(iphdr->saddr, ntohs(tcphdr->source));
        _M_server.assign(iphdr->daddr, ntohs(tcphdr->dest));

        _M_state = s;

        _M_timestamp.creation = timestamp;
      }

      inline void connection::assign(const struct ip6_hdr* iphdr,
                                     const struct tcphdr* tcphdr,
                                     enum state s,
                                     uint64_t timestamp)
      {
        _M_client.assign(iphdr->ip6_src, ntohs(tcphdr->source));
        _M_server.assign(iphdr->ip6_dst, ntohs(tcphdr->dest));

        _M_state = s;

        _M_timestamp.creation = timestamp;
      }

      inline bool connection::operator==(const connection& conn) const
      {
        return ((_M_client == conn._M_client) && (_M_server == conn._M_server));
      }

      inline bool connection::match(const struct iphdr* iphdr,
                                    const struct tcphdr* tcphdr) const
      {
        direction dir;
        return match(iphdr, tcphdr, dir);
      }

      inline bool connection::match(const struct iphdr* iphdr,
                                    const struct tcphdr* tcphdr,
                                    direction& dir) const
      {
        const uint16_t source = ntohs(tcphdr->source);
        const uint16_t dest = ntohs(tcphdr->dest);

        if ((_M_client.port() == source) &&
            (_M_server.port() == dest) &&
            (_M_client.address() == iphdr->saddr) &&
            (_M_server.address() == iphdr->daddr)) {
          dir = direction::from_client;
          return true;
        } else if ((_M_client.port() == dest) &&
                   (_M_server.port() == source) &&
                   (_M_client.address() == iphdr->daddr) &&
                   (_M_server.address() == iphdr->saddr)) {
          dir = direction::from_server;
          return true;
        } else {
          return false;
        }
      }

      inline bool connection::match(const struct ip6_hdr* iphdr,
                                    const struct tcphdr* tcphdr) const
      {
        direction dir;
        return match(iphdr, tcphdr, dir);
      }

      inline bool connection::match(const struct ip6_hdr* iphdr,
                                    const struct tcphdr* tcphdr,
                                    direction& dir) const
      {
        const uint16_t source = ntohs(tcphdr->source);
        const uint16_t dest = ntohs(tcphdr->dest);

        if ((_M_client.port() == source) &&
            (_M_server.port() == dest) &&
            (_M_client.address() == iphdr->ip6_src) &&
            (_M_server.address() == iphdr->ip6_dst)) {
          dir = direction::from_client;
          return true;
        } else if ((_M_client.port() == dest) &&
                   (_M_server.port() == source) &&
                   (_M_client.address() == iphdr->ip6_dst) &&
                   (_M_server.address() == iphdr->ip6_src)) {
          dir = direction::from_server;
          return true;
        } else {
          return false;
        }
      }

      inline const endpoint& connection::client() const
      {
        return _M_client;
      }

      inline const endpoint& connection::server() const
      {
        return _M_server;
      }

      inline enum connection::state connection::state() const
      {
        return _M_state;
      }

      inline void connection::state(enum state s)
      {
        _M_state = s;
      }

      inline uint64_t connection::creation_timestamp() const
      {
        return _M_timestamp.creation;
      }

      inline uint64_t connection::last_timestamp() const
      {
        return _M_timestamp.last_packet;
      }

      inline void connection::touch(uint64_t timestamp)
      {
        _M_timestamp.last_packet = timestamp;
      }
    }
  }
}

#endif // NET_IP_TCP_CONNECTION_H
