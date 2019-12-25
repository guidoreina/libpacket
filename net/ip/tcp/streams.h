#ifndef NET_IP_TCP_STREAMS_H
#define NET_IP_TCP_STREAMS_H

#include "net/ip/tcp/connections.h"
#include "net/ip/tcp/stream.h"

namespace net {
  namespace ip {
    namespace tcp {
      // TCP streams.
      class streams {
        public:
          // Constructor.
          streams();

          // Destructor.
          ~streams();

          // Initialize.
          bool init(stream::beginstreamfn_t beginstreamfn,
                    stream::endstreamfn_t endstreamfn,
                    stream::payloadfn_t payloadfn,
                    stream::gapfn_t gapfn,
                    size_t size = connections::default_size,
                    size_t maxconns = connections::default_max_connections,
                    uint64_t timeout = connections::default_timeout,
                    uint64_t time_wait = connections::default_time_wait);

          // Process TCP segment.
          void process(const iphdr* iphdr,
                       const tcphdr* tcphdr,
                       const void* payload,
                       uint16_t payloadlen,
                       uint64_t timestamp);

          void process(const ip6_hdr* iphdr,
                       const tcphdr* tcphdr,
                       const void* payload,
                       uint16_t payloadlen,
                       uint64_t timestamp);

          void process(uint32_t hash,
                       const iphdr* iphdr,
                       const tcphdr* tcphdr,
                       const void* payload,
                       uint16_t payloadlen,
                       uint64_t timestamp);

          void process(uint32_t hash,
                       const ip6_hdr* iphdr,
                       const tcphdr* tcphdr,
                       const void* payload,
                       uint16_t payloadlen,
                       uint64_t timestamp);

          // Remove expired connections.
          void remove_expired(uint64_t now);

        private:
          // Connections.
          connections _M_connections;

          // Streams.
          stream* _M_streams = nullptr;

          // Segment allocator.
          segments _M_allocator;

          // Process TCP segment.
          template<typename IpHeader>
          void process_(uint32_t hash,
                        const IpHeader* iphdr,
                        const tcphdr* tcphdr,
                        const void* payload,
                        uint16_t payloadlen,
                        uint64_t timestamp);

          // Process expired connection.
          static void expired(const connection* conn, void* user);

          // Terminate connection.
          void terminate(const connection* conn);

          // Disable copy constructor and assignment operator.
          streams(const streams&) = delete;
          streams& operator=(const streams&) = delete;
      };

      inline streams::streams()
        : _M_connections(expired, this)
      {
      }

      inline void streams::remove_expired(uint64_t now)
      {
        _M_connections.remove_expired(now);
      }

      inline void streams::expired(const connection* conn, void* user)
      {
        static_cast<streams*>(user)->terminate(conn);
      }

      inline void streams::terminate(const connection* conn)
      {
        // Terminate streams.
        _M_streams[conn->id() * 2].terminate();
        _M_streams[(conn->id() * 2) + 1].terminate();
      }
    }
  }
}

#endif // NET_IP_TCP_STREAMS_H
