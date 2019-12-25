#ifndef NET_IP_LIMITS_H
#define NET_IP_LIMITS_H

namespace net {
  namespace ip {
    static constexpr const size_t packet_max_len = 256 * 1024;
    static constexpr const size_t domain_name_max_len = 255;
  }
}

#endif // NET_IP_LIMITS_H
