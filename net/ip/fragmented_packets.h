#ifndef NET_IP_FRAGMENTED_PACKETS_H
#define NET_IP_FRAGMENTED_PACKETS_H

#include <string.h>
#include "net/ip/fragmented_packet.h"

namespace net {
  namespace ip {
    // IP fragmented packets.
    class fragmented_packets {
      public:
        // Constructor.
        fragmented_packets() = default;

        // Destructor.
        ~fragmented_packets();

        // Clear.
        void clear();

        // Add fragment.
        // Return a fragmented packet when it is complete.
        const fragmented_packet* add(const void* iphdr,
                                     uint16_t iphdrlen,
                                     uint32_t id,
                                     uint64_t timestamp,
                                     uint16_t offset,
                                     const void* data,
                                     uint16_t len,
                                     bool last);

      private:
        // Maximum number of fragmented packets.
        static constexpr const size_t max_packets = 1024;

        // Fragmented packets in use.
        fragmented_packet* _M_packets[max_packets];

        // Number of fragmented packets in use.
        size_t _M_npackets = 0;

        // Free fragmented packets.
        fragmented_packet* _M_free[max_packets];

        // Number of free fragmented packets.
        size_t _M_nfree = 0;

        // Get fragmented packet.
        ssize_t get(uint32_t id, uint64_t timestamp);

        // Free fragmented packet.
        void free(size_t idx, fragmented_packet* pkt);

        // Allocate fragments.
        bool allocate();

        // Disable copy constructor and assignment operator.
        fragmented_packets(const fragmented_packets&) = delete;
        fragmented_packets& operator=(const fragmented_packets&) = delete;
    };

    inline fragmented_packets::~fragmented_packets()
    {
      clear();
    }

    inline void fragmented_packets::free(size_t idx, fragmented_packet* pkt)
    {
      // If not the last fragmented packet...
      if (idx < --_M_npackets) {
        memmove(_M_packets + idx,
                _M_packets + idx + 1,
                (_M_npackets - idx) * sizeof(fragmented_packet*));
      }

      _M_free[_M_nfree++] = pkt;
    }
  }
}

#endif // NET_IP_FRAGMENTED_PACKETS_H
