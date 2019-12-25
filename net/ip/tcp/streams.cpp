#include <new>
#include "net/ip/tcp/streams.h"

net::ip::tcp::streams::~streams()
{
  if (_M_streams) {
    // Two streams per connection.
    const size_t nstreams = _M_connections.maximum_number_connections() * 2;

    // For each stream...
    for (size_t i = nstreams; i > 0; i--) {
      stream& stream = _M_streams[i - 1];

      // Terminate old stream (if any).
      stream.terminate();

      // Call destructor.
      stream.~stream();
    }

    free(_M_streams);
  }
}

bool net::ip::tcp::streams::init(stream::beginstreamfn_t beginstreamfn,
                                 stream::endstreamfn_t endstreamfn,
                                 stream::payloadfn_t payloadfn,
                                 stream::gapfn_t gapfn,
                                 size_t size,
                                 size_t maxconns,
                                 uint64_t timeout,
                                 uint64_t time_wait)
{
  // Initialize connections.
  if (_M_connections.init(size, maxconns, timeout, time_wait)) {
    // Two streams per connection.
    const size_t nstreams = maxconns * 2;

    // Create streams.
    void* buf = malloc(nstreams * sizeof(stream));
    if (buf) {
      _M_streams = static_cast<stream*>(buf);

      // Initialize streams.
      for (size_t i = nstreams; i > 0; i--) {
        // Call constructor.
        new (&_M_streams[i - 1]) stream(_M_allocator);
      }

      // Set callbacks.
      stream::callbacks(beginstreamfn, endstreamfn, payloadfn, gapfn);

      return true;
    }
  }

  return false;
}

void net::ip::tcp::streams::process(const iphdr* iphdr,
                                    const tcphdr* tcphdr,
                                    const void* payload,
                                    uint16_t payloadlen,
                                    uint64_t timestamp)
{
  process_(hash(iphdr, tcphdr), iphdr, tcphdr, payload, payloadlen, timestamp);
}

void net::ip::tcp::streams::process(const ip6_hdr* iphdr,
                                    const tcphdr* tcphdr,
                                    const void* payload,
                                    uint16_t payloadlen,
                                    uint64_t timestamp)
{
  process_(hash(iphdr, tcphdr), iphdr, tcphdr, payload, payloadlen, timestamp);
}

void net::ip::tcp::streams::process(uint32_t hash,
                                    const iphdr* iphdr,
                                    const tcphdr* tcphdr,
                                    const void* payload,
                                    uint16_t payloadlen,
                                    uint64_t timestamp)
{
  process_(hash, iphdr, tcphdr, payload, payloadlen, timestamp);
}

void net::ip::tcp::streams::process(uint32_t hash,
                                    const ip6_hdr* iphdr,
                                    const tcphdr* tcphdr,
                                    const void* payload,
                                    uint16_t payloadlen,
                                    uint64_t timestamp)
{
  process_(hash, iphdr, tcphdr, payload, payloadlen, timestamp);
}

template<typename IpHeader>
void net::ip::tcp::streams::process_(uint32_t hash,
                                     const IpHeader* iphdr,
                                     const tcphdr* tcphdr,
                                     const void* payload,
                                     uint16_t payloadlen,
                                     uint64_t timestamp)
{
  // Process TCP segment.
  direction dir;
  const connection* conn = _M_connections.process(hash,
                                                  iphdr,
                                                  tcphdr,
                                                  timestamp,
                                                  dir);

  // If the TCP segment could be processed...
  if (conn) {
    // Get stream.
    stream&
      stream = _M_streams[(conn->id() * 2) + static_cast<size_t>(dir)];

    // If it is the first segment of the stream...
    if (conn->number_packets(dir) == 1) {
      // Terminate old stream (if any).
      stream.terminate();

      // Initialize stream.
      if (!stream.init(conn, dir)) {
        return;
      }
    }

    // If the connection has not been closed...
    if (conn->state() != connection::state::closed) {
      // Add segment to the stream.
      stream.add(ntohl(tcphdr->seq), tcphdr->th_flags, payload, payloadlen);
    } else {
      // Connection has been terminated.
      terminate(conn);
    }
  }
}
