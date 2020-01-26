#ifndef NET_IP_SERVICES_H
#define NET_IP_SERVICES_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "net/ip/addresses.h"

namespace net {
  namespace ip {
    // IP service.
    struct service {
      // Service extension.
      static constexpr const char* const extension = "svc";

      // Service id.
      typedef unsigned identifier;
      identifier id;

      // Service name.
      char* name;

      // Direction.
      enum class direction {
        upload,
        download
      };
    };

    // IP services.
    class services {
      public:
        // Constructor.
        services() = default;

        // Destructor.
        ~services();

        // Load services from directory.
        // Filenames have the format:
        //   <service-id>_<service-name>.svc
        //   <service-id> ::= <number>
        //
        // Each service file contains lines with the following format:
        // <ip-address-or-domain>[,<from-port>[,<to-port>]]
        // <ip-address-or-domain> ::= <ip-address> | <domain>
        // <ip-address> ::= <ipv4-address-or-ipv6-address>[/<prefix-length>]
        // <ipv4-address-or-ipv6-address> ::= <ipv4-address> | <ipv6-address>
        // <from-port> ::= <port>
        // <to-port> ::= <port>
        // <prefix-length> ::= 1 .. 32 (for IPv4 addresses) |
        //                     1 .. 128 (for IPv6 addresses)
        bool load(const char* dirname);

        // Process DNS response (only if domains have been used).
        bool process_dns(const void* msg, size_t len);

        // Find service.
        bool find(const struct iphdr* iphdr,
                  const struct tcphdr* tcphdr,
                  service::identifier& id,
                  service::direction& dir) const;

        bool find(const struct iphdr* iphdr,
                  const struct udphdr* udphdr,
                  service::identifier& id,
                  service::direction& dir) const;

        bool find(const struct ip6_hdr* iphdr,
                  const struct tcphdr* tcphdr,
                  service::identifier& id,
                  service::direction& dir) const;

        bool find(const struct ip6_hdr* iphdr,
                  const struct udphdr* udphdr,
                  service::identifier& id,
                  service::direction& dir) const;

        // Get service name.
        const char* name(service::identifier id) const;

      private:
        // Service allocation.
        static constexpr const size_t allocation = 64;

        // Field separator.
        static constexpr const char separator = ',';

        // Services.
        service* _M_services = nullptr;
        size_t _M_size = 0;
        size_t _M_used = 0;

        // Ports.
        struct ports {
          in_port_t from_port;
          in_port_t to_port;

          // Service id.
          service::identifier id;
        };

        // IP addresses.
        addresses<ports> _M_addresses;

        // Domain.
        struct domain {
          char* name;
          struct ports ports;
        };

        // Domains.
        class domains {
          public:
            // Constructor.
            domains() = default;

            // Destructor.
            ~domains();

            // Empty?
            bool empty() const;

            // Add domain.
            bool add(const char* name, size_t len, const ports& ports);

            // Find domain.
            const ports* find(const char* name) const;

          private:
            // Domain allocation.
            static constexpr const size_t allocation = 64;

            domain* _M_domains = nullptr;
            size_t _M_size = 0;
            size_t _M_used = 0;

            // Find domain.
            bool find(const char* name, size_t& pos) const;

            // Allocate domains.
            bool allocate();

            // Disable copy constructor and assignment operator.
            domains(const domains&) = delete;
            domains& operator=(const domains&) = delete;
        };

        domains _M_domains;

        // Find service.
        bool find(uint32_t saddr,
                  in_port_t sport,
                  uint32_t daddr,
                  in_port_t dport,
                  service::identifier& id,
                  service::direction& dir) const;

        bool find(const struct in6_addr& saddr,
                  in_port_t sport,
                  const struct in6_addr& daddr,
                  in_port_t dport,
                  service::identifier& id,
                  service::direction& dir) const;

        // Load service.
        bool load_service(service::identifier id,
                          const char* name,
                          size_t len,
                          const char* filename);

        // Add service.
        bool add(service::identifier id, const char* name, size_t len);

        // Find service.
        bool find(service::identifier id, size_t& pos) const;

        // Allocate services.
        bool allocate();

        // Disable copy constructor and assignment operator.
        services(const services&) = delete;
        services& operator=(const services&) = delete;
    };

    inline bool services::find(const struct iphdr* iphdr,
                               const struct tcphdr* tcphdr,
                               service::identifier& id,
                               service::direction& dir) const
    {
      return find(iphdr->saddr,
                  ntohs(tcphdr->source),
                  iphdr->daddr,
                  ntohs(tcphdr->dest),
                  id,
                  dir);
    }

    inline bool services::find(const struct iphdr* iphdr,
                               const struct udphdr* udphdr,
                               service::identifier& id,
                               service::direction& dir) const
    {
      return find(iphdr->saddr,
                  ntohs(udphdr->source),
                  iphdr->daddr,
                  ntohs(udphdr->dest),
                  id,
                  dir);
    }

    inline bool services::find(const struct ip6_hdr* iphdr,
                               const struct tcphdr* tcphdr,
                               service::identifier& id,
                               service::direction& dir) const
    {
      return find(iphdr->ip6_src,
                  ntohs(tcphdr->source),
                  iphdr->ip6_dst,
                  ntohs(tcphdr->dest),
                  id,
                  dir);
    }

    inline bool services::find(const struct ip6_hdr* iphdr,
                               const struct udphdr* udphdr,
                               service::identifier& id,
                               service::direction& dir) const
    {
      return find(iphdr->ip6_src,
                  ntohs(udphdr->source),
                  iphdr->ip6_dst,
                  ntohs(udphdr->dest),
                  id,
                  dir);
    }

    inline const char* services::name(service::identifier id) const
    {
      size_t pos;
      return find(id, pos) ? _M_services[pos].name : nullptr;
    }

    inline bool services::domains::empty() const
    {
      return (_M_used == 0);
    }

    inline
    const services::ports* services::domains::find(const char* name) const
    {
      size_t pos;
      return find(name, pos) ? &_M_domains[pos].ports : nullptr;
    }
  }
}

#endif // NET_IP_SERVICES_H
