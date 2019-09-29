#ifndef NET_IP_PACKETS_H
#define NET_IP_PACKETS_H

#include "net/ip/packet.h"

namespace net {
  namespace ip {
    // IP packets.
    class packets {
      public:
        // Constructor.
        packets() = default;

        // Destructor.
        ~packets();

        // Get free packet.
        packet* get();

        // Add packet.
        bool add(packet* pkt);

        // Get number of packets
        size_t count() const;

        // Get packet at position
        const packet* get(size_t idx) const;

      private:
        // Packet allocation.
        static constexpr const size_t packet_allocation = 32 * 1024;

        // Packets in use.
        packet** _M_packets = nullptr;
        size_t _M_size = 0;
        size_t _M_used = 0;

        // Available packets.
        packet** _M_free = nullptr;

        // Number of packets available.
        size_t _M_nfree = 0;

        // Allocate packets.
        bool allocate();

        // Disable copy constructor and assignment operator.
        packets(const packets&) = delete;
        packets& operator=(const packets&) = delete;
    };

    inline packet* packets::get()
    {
      // If there are available packets...
      if (_M_nfree > 0) {
        return _M_free[--_M_nfree];
      } else {
        return allocate() ? _M_free[--_M_nfree] : nullptr;
      }
    }

    inline size_t packets::count() const
    {
      return _M_used;
    }

    inline const packet* packets::get(size_t idx) const
    {
      return (idx < _M_used) ? _M_packets[idx] : nullptr;
    }
  }
}

#endif // NET_IP_PACKETS_H
