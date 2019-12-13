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
          connection(const struct iphdr* iphdr, const struct tcphdr* tcphdr);
          connection(const struct ip6_hdr* iphdr, const struct tcphdr* tcphdr);

          // Destructor.
          ~connection() = default;

          // Assign.
          void assign(const struct iphdr* iphdr, const struct tcphdr* tcphdr);
          void assign(const struct ip6_hdr* iphdr, const struct tcphdr* tcphdr);

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
          static bool process(direction dir,
                              uint8_t flags,
                              enum state& s,
                              originator& active_closer);

          bool process(direction dir, uint8_t flags);

          // Get client.
          const endpoint& client() const;

          // Get server.
          const endpoint& server() const;

          // Get connection state.
          enum state state() const;

        private:
          // Client.
          endpoint _M_client;

          // Server.
          endpoint _M_server;

          // Connection state.
          enum state _M_state;

          // Who initiates the connection shutdown?
          originator _M_active_closer;

          // Disable copy constructor and assignment operator.
          connection(const connection&) = delete;
          connection& operator=(const connection&) = delete;
      };

      inline connection::connection(const struct iphdr* iphdr,
                                    const struct tcphdr* tcphdr)
        : _M_client(iphdr->saddr, ntohs(tcphdr->source)),
          _M_server(iphdr->daddr, ntohs(tcphdr->dest)),
          _M_state(state::connection_requested)
      {
      }

      inline connection::connection(const struct ip6_hdr* iphdr,
                                    const struct tcphdr* tcphdr)
        : _M_client(iphdr->ip6_src, ntohs(tcphdr->source)),
          _M_server(iphdr->ip6_dst, ntohs(tcphdr->dest)),
          _M_state(state::connection_requested)
      {
      }

      inline void connection::assign(const struct iphdr* iphdr,
                                     const struct tcphdr* tcphdr)
      {
        _M_client.assign(iphdr->saddr, ntohs(tcphdr->source));
        _M_server.assign(iphdr->daddr, ntohs(tcphdr->dest));

        _M_state = state::connection_requested;
      }

      inline void connection::assign(const struct ip6_hdr* iphdr,
                                     const struct tcphdr* tcphdr)
      {
        _M_client.assign(iphdr->ip6_src, ntohs(tcphdr->source));
        _M_server.assign(iphdr->ip6_dst, ntohs(tcphdr->dest));

        _M_state = state::connection_requested;
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

      inline bool connection::process(direction dir, uint8_t flags)
      {
        return process(dir, flags, _M_state, _M_active_closer);
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
    }
  }
}

#endif // NET_IP_TCP_CONNECTION_H
