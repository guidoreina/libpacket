#ifndef NET_IP_PROTOCOL_H
#define NET_IP_PROTOCOL_H

#include <stdint.h>
#include <netinet/in.h>

namespace net {
  namespace ip {
    // IP protocol.
    enum class protocol : uint8_t {
      tcp    = IPPROTO_TCP,
      udp    = IPPROTO_UDP,
      icmp   = IPPROTO_ICMP,
      icmpv6 = IPPROTO_ICMPV6
    };
  }
}

#endif // NET_IP_PROTOCOL_H
