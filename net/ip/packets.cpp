#include <stdlib.h>
#include <new>
#include "net/ip/packets.h"

net::ip::packets::~packets()
{
  if (_M_packets) {
    for (; _M_used > 0; _M_used--) {
      delete _M_packets[_M_used - 1];
    }

    free(_M_packets);
  }

  if (_M_free) {
    for (; _M_nfree > 0; _M_nfree--) {
      delete _M_free[_M_nfree - 1];
    }

    free(_M_free);
  }
}

bool net::ip::packets::add(packet* pkt)
{
  if (_M_used < _M_size) {
    _M_packets[_M_used++] = pkt;

    return true;
  } else {
    size_t size = (_M_size > 0) ? _M_size * 2 : packet_allocation;

    packet** packets;
    if ((packets = static_cast<packet**>(
                     realloc(_M_packets, size * sizeof(packet*))
                   )) != nullptr) {
      _M_packets = packets;
      _M_size = size;

      _M_packets[_M_used++] = pkt;

      return true;
    } else {
      return false;
    }
  }
}

bool net::ip::packets::allocate()
{
  if ((_M_free) || ((_M_free = static_cast<packet**>(
                                 malloc(packet_allocation * sizeof(packet*))
                               )) != nullptr)) {
    for (; _M_nfree < packet_allocation; _M_nfree++) {
      if ((_M_free[_M_nfree] = new (std::nothrow) packet()) == nullptr) {
        return (_M_nfree > 0);
      }
    }

    return true;
  }

  return false;
}
