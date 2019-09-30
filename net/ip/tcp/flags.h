#ifndef NET_IP_TCP_FLAGS_H
#define NET_IP_TCP_FLAGS_H

#include <stdint.h>

namespace net {
  namespace ip {
    namespace tcp {
      static constexpr const uint8_t ack = 0x10;
      static constexpr const uint8_t rst = 0x04;
      static constexpr const uint8_t syn = 0x02;
      static constexpr const uint8_t fin = 0x01;

      static constexpr const uint8_t flag_mask = ack | rst | syn | fin;
    }
  }
}

#endif // NET_IP_TCP_FLAGS_H
