#ifndef NET_IP_PACKET_H
#define NET_IP_PACKET_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "net/ip/version.h"

namespace net {
  namespace ip {
    // IP packet.
    class packet {
      friend class parser;

      public:
        // Constructor.
        packet() = default;

        // Destructor.
        ~packet();

        // Get packet timestamp.
        uint64_t timestamp() const;

        // Get length of the IP packet.
        uint16_t length() const;

        // Get IP version.
        ip::version version() const;

        // Get pointer to the layer 2 protocol as an IPv4 header.
        const struct iphdr* ipv4() const;

        // Get pointer to the layer 2 protocol as an IPv6 header.
        const struct ip6_hdr* ipv6() const;

        // Get pointer to the layer 2 protocol.
        const void* l2() const;

        // Get protocol.
        uint8_t protocol() const;

        // Get pointer to the layer 3 protocol as a TCP header.
        const struct tcphdr* tcp() const;

        // Get pointer to the layer 3 protocol as a UDP header.
        const struct udphdr* udp() const;

        // Get pointer to the layer 3 protocol as an ICMP header.
        const struct icmphdr* icmp() const;

        // Get pointer to the layer 3 protocol as an ICMPv6 header.
        const struct icmp6_hdr* icmpv6() const;

        // Get pointer to the layer 3 protocol.
        const void* l3() const;

        // Get pointer to the layer 4 protocol.
        const void* l4() const;

        // Get length of the layer 4 protocol.
        uint16_t l4length() const;

        // Has the packet payload?
        bool has_payload() const;

        // Is the packet a TCP segment?
        bool is_tcp() const;

        // Is the packet an UDP datagram?
        bool is_udp() const;

        // Is the packet an ICMP datagram?
        bool is_icmp() const;

        // Is the packet an ICMPv6 datagram?
        bool is_icmpv6() const;

      private:
        // Packet timestamp, as the number of microseconds since the Epoch,
        // 1970-01-01 00:00:00 +0000 (UTC).
        uint64_t _M_timestamp;

        // Length of the IP packet.
        uint16_t _M_length;

        // IP version.
        ip::version _M_version;

        // Pointer to the layer 2 protocol.
        union {
          const struct iphdr* ipv4;
          const struct ip6_hdr* ipv6;
          const void* buf;
        } _M_l2;

        // Layer 3 protocol.
        uint8_t _M_protocol;

        // Pointer to the layer 3 protocol.
        union {
          const struct tcphdr* tcp;
          const struct udphdr* udp;
          const struct icmphdr* icmp;
          const struct icmp6_hdr* icmpv6;
          const void* buf;
        } _M_l3;

        // Pointer to the layer 4 protocol.
        const void* _M_l4;

        // Packet is stored in '_M_buf' when it was fragmented.
        void* _M_buf = nullptr;

        // Disable copy constructor and assignment operator.
        packet(const packet&) = delete;
        packet& operator=(const packet&) = delete;
    };

    inline packet::~packet()
    {
      if (_M_buf) {
        free(_M_buf);
      }
    }

    inline uint64_t packet::timestamp() const
    {
      return _M_timestamp;
    }

    inline uint16_t packet::length() const
    {
      return _M_length;
    }

    inline ip::version packet::version() const
    {
      return _M_version;
    }

    inline const struct iphdr* packet::ipv4() const
    {
      return _M_l2.ipv4;
    }

    inline const struct ip6_hdr* packet::ipv6() const
    {
      return _M_l2.ipv6;
    }

    inline const void* packet::l2() const
    {
      return _M_l2.buf;
    }

    inline uint8_t packet::protocol() const
    {
      return _M_protocol;
    }

    inline const struct tcphdr* packet::tcp() const
    {
      return _M_l3.tcp;
    }

    inline const struct udphdr* packet::udp() const
    {
      return _M_l3.udp;
    }

    inline const struct icmphdr* packet::icmp() const
    {
      return _M_l3.icmp;
    }

    inline const struct icmp6_hdr* packet::icmpv6() const
    {
      return _M_l3.icmpv6;
    }

    inline const void* packet::l3() const
    {
      return _M_l3.buf;
    }

    inline const void* packet::l4() const
    {
      return _M_l4;
    }

    inline uint16_t packet::l4length() const
    {
      return static_cast<uint16_t>(static_cast<const uint8_t*>(_M_l2.buf) +
                                   _M_length -
                                   static_cast<const uint8_t*>(_M_l4));
    }

    inline bool packet::has_payload() const
    {
      return (l4length() > 0);
    }

    inline bool packet::is_tcp() const
    {
      return (_M_protocol == IPPROTO_TCP);
    }

    inline bool packet::is_udp() const
    {
      return (_M_protocol == IPPROTO_UDP);
    }

    inline bool packet::is_icmp() const
    {
      return (_M_protocol == IPPROTO_ICMP);
    }

    inline bool packet::is_icmpv6() const
    {
      return (_M_protocol == IPPROTO_ICMPV6);
    }
  }
}

#endif // NET_IP_PACKET_H
