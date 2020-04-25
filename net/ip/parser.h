#ifndef NET_IP_PARSER_H
#define NET_IP_PARSER_H

#include "net/ip/packet.h"
#include "net/ip/fragmented_packets.h"

namespace net {
  namespace ip {
    // IP parser.
    class parser {
      public:
        // Constructor.
        parser() = default;

        // Destructor.
        ~parser() = default;

        // Process ethernet frame.
        bool process_ethernet(const void* buf,
                              uint32_t len,
                              uint64_t timestamp,
                              packet* pkt);

        // Process IPv4 packet.
        bool process_ipv4(const void* buf,
                          uint16_t len,
                          uint64_t timestamp,
                          packet* pkt);

        // Process IPv6 packet.
        bool process_ipv6(const void* buf,
                          uint16_t len,
                          uint64_t timestamp,
                          packet* pkt);

      private:
        // Fragmented packets.
        fragmented_packets _M_fragmented_packets;

        // Process non-fragmented IPv4 packet.
        bool process_non_fragmented_ipv4(const struct iphdr* iphdr,
                                         uint16_t iplen,
                                         packet* pkt);

        // Process TCP segment.
        bool process_tcp(packet* pkt, uint16_t iphdrlen);

        // Process UDP datagram.
        bool process_udp(packet* pkt, uint16_t iphdrlen);

        // Process ICMP datagram.
        bool process_icmp(packet* pkt, uint16_t iphdrlen);

        // Process ICMPv6 datagram.
        bool process_icmpv6(packet* pkt, uint16_t iphdrlen);

        // Build packet from fragmented packet.
        static bool build(const fragmented_packet* fp, packet* pkt);

        // Is extension header?
        static bool is_extension_header(uint8_t nxt);

        // Disable copy constructor and assignment operator.
        parser(const parser&) = delete;
        parser& operator=(const parser&) = delete;
    };

    inline bool parser::is_extension_header(uint8_t nxt)
    {
      switch (nxt) {
        case IPPROTO_HOPOPTS:  //   0: IPv6 hop-by-hop options.
        case IPPROTO_DSTOPTS:  //  60: IPv6 destination options.
        case IPPROTO_ROUTING:  //  43: IPv6 routing header.
        case IPPROTO_FRAGMENT: //  44: IPv6 fragmentation header.
        case IPPROTO_MH:       // 135: IPv6 mobility header.
        case 139:              // 139: Host Identity Protocol.
        case 140:              // 140: Shim6 Protocol.
          return true;
        default:
          return false;
      }
    }
  }
}

#endif // NET_IP_PARSER_H
