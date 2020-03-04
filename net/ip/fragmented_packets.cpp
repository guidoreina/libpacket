#include <new>
#include "net/ip/fragmented_packets.h"

void net::ip::fragmented_packets::clear()
{
  for (; _M_npackets > 0; _M_npackets--) {
    delete _M_packets[_M_npackets - 1];
  }

  for (; _M_nfree > 0; _M_nfree--) {
    delete _M_free[_M_nfree - 1];
  }
}

const net::ip::fragmented_packet*
net::ip::fragmented_packets::add(const void* iphdr,
                                 uint16_t iphdrlen,
                                 uint32_t id,
                                 uint64_t timestamp,
                                 uint16_t offset,
                                 const void* data,
                                 uint16_t len,
                                 bool last)
{
  // Get fragmented packet.
  ssize_t idx;
  if ((len > 0) && ((idx = get(id, timestamp)) != -1)) {
    fragmented_packet* pkt = _M_packets[idx];
    switch (pkt->add(iphdr, iphdrlen, id, timestamp, offset, data, len, last)) {
      case fragmented_packet::result::complete:
        free(idx, pkt);
        return pkt;
      case fragmented_packet::result::success:
      case fragmented_packet::result::duplicated_fragment:
        return nullptr;
      case fragmented_packet::result::invalid_fragment:
      case fragmented_packet::result::no_memory:
        free(idx, pkt);
        return nullptr;
    }
  }

  return nullptr;
}

ssize_t net::ip::fragmented_packets::get(uint32_t id, uint64_t timestamp)
{
  // Find fragmented packet.
  size_t i = 0;
  while (i < _M_npackets) {
    // If it is the fragmented packet we are searching for...
    if (id == _M_packets[i]->id()) {
      // If the fragmented packet is not too old...
      if (_M_packets[i]->timestamp() + fragmented_packet::max_age >=
          timestamp) {
        return i;
      } else {
        free(i, _M_packets[i]);

        break;
      }
    } else {
      // If the fragmented packet is not too old...
      if (_M_packets[i]->timestamp() + fragmented_packet::max_age >=
          timestamp) {
        i++;
      } else {
        free(i, _M_packets[i]);
      }
    }
  }

  // Fragmented packet not found.

  // If there are free fragmented packets...
  if ((_M_nfree > 0) || ((_M_npackets == 0) && (allocate()))) {
    // Get last free fragmented packet.
    fragmented_packet* pkt = _M_free[--_M_nfree];

    // Clear fragmented packet.
    pkt->clear();

    // Add fragmented packet.
    _M_packets[_M_npackets++] = pkt;

    return _M_npackets - 1;
  } else {
    return -1;
  }
}

bool net::ip::fragmented_packets::allocate()
{
  // Allocate fragmented packets.
  for (; _M_nfree < max_packets; _M_nfree++) {
    if ((_M_free[_M_nfree] = new (std::nothrow) fragmented_packet()) ==
        nullptr) {
      return (_M_nfree > 0);
    }
  }

  return true;
}
