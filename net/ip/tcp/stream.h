#ifndef NET_IP_TCP_STREAM_H
#define NET_IP_TCP_STREAM_H

#include "net/ip/tcp/segments.h"
#include "net/ip/tcp/connection.h"

namespace net {
  namespace ip {
    namespace tcp {
      // TCP stream.
      class stream {
        public:
          // Begin stream callback.
          typedef bool (*beginstreamfn_t)(const connection*, direction, void*&);

          // End stream callback.
          typedef void (*endstreamfn_t)(const connection*, direction, void*);

          // Payload callback.
          typedef bool (*payloadfn_t)(const void*,
                                      uint16_t,
                                      uint64_t,
                                      const connection*,
                                      direction,
                                      void*);

          // Gap callback.
          typedef bool (*gapfn_t)(uint32_t,
                                  uint64_t,
                                  const connection*,
                                  direction,
                                  void*);

          // Set callbacks.
          static void callbacks(beginstreamfn_t beginstreamfn,
                                endstreamfn_t endstreamfn,
                                payloadfn_t payloadfn,
                                gapfn_t gapfn);

          // Constructor.
          stream(segments& allocator);

          // Destructor.
          ~stream();

          // Clear.
          void clear();

          // Initialize.
          bool init(const connection* conn, direction dir);

          // Add segment.
          bool add(uint32_t seq,
                   uint8_t tcpflags,
                   const void* payload,
                   uint16_t payloadlen);

          // Terminate stream.
          void terminate();

        private:
          // Maximum number of queued segments.
          static constexpr const size_t max_queued_segments = 4 * 1024;

          // Segment allocator.
          segments& _M_allocator;

          // Next sequence number.
          uint32_t _M_nxt;

          // First segment.
          segment* _M_first = nullptr;

          // Last segment.
          segment* _M_last = nullptr;

          // Number of queued segments.
          size_t _M_nsegments = 0;

          // Current offset in the stream.
          uint64_t _M_offset = 0;

          // Connection.
          const connection* _M_connection = nullptr;

          // Direction.
          direction _M_direction;

          // User pointer.
          void* _M_user = nullptr;

          // Ignore stream?
          bool _M_ignore = false;

          // Begin stream callback.
          static beginstreamfn_t _M_beginstreamfn;

          // End stream callback.
          static endstreamfn_t _M_endstreamfn;

          // Payload callback.
          static payloadfn_t _M_payloadfn;

          // Gap callback.
          static gapfn_t _M_gapfn;

          // Notify payload.
          bool notify_payload(const void* payload, uint16_t payloadlen);

          // Insert segment.
          bool insert(segment* prev,
                      uint32_t seq,
                      const void* payload,
                      uint16_t payloadlen);

          // Check segments.
          bool check_segments();

          // Notify user rest of payloads.
          void flush();

          // Notify gap.
          bool notify_gap();

          // Less than?
          static bool less_than(uint32_t seq1, uint32_t seq2);

          // Less or equal than?
          static bool less_or_equal_than(uint32_t seq1, uint32_t seq2);

          // Greater than?
          static bool greater_than(uint32_t seq1, uint32_t seq2);

          // Greater or equal than?
          static bool greater_or_equal_than(uint32_t seq1, uint32_t seq2);

          // Equal?
          static bool equal(uint32_t seq1, uint32_t seq2);

          // Disable copy constructor and assignment operator.
          stream(const stream&) = delete;
          stream& operator=(const stream&) = delete;
      };

      inline void stream::callbacks(beginstreamfn_t beginstreamfn,
                                    endstreamfn_t endstreamfn,
                                    payloadfn_t payloadfn,
                                    gapfn_t gapfn)
      {
        _M_beginstreamfn = beginstreamfn;
        _M_endstreamfn = endstreamfn;
        _M_payloadfn = payloadfn;
        _M_gapfn = gapfn;
      }

      inline stream::stream(segments& allocator)
        : _M_allocator(allocator)
      {
      }

      inline stream::~stream()
      {
        clear();
      }

      inline bool stream::init(const connection* conn, direction dir)
      {
        // Notify begin of stream.
        if (_M_beginstreamfn(conn, dir, _M_user)) {
          _M_connection = conn;
          _M_direction = dir;

          return true;
        } else {
          _M_ignore = true;
          return false;
        }
      }

      inline bool stream::less_than(uint32_t seq1, uint32_t seq2)
      {
        return (static_cast<int32_t>(seq1 - seq2) < 0);
      }

      inline bool stream::less_or_equal_than(uint32_t seq1, uint32_t seq2)
      {
        return (static_cast<int32_t>(seq1 - seq2) <= 0);
      }

      inline bool stream::greater_than(uint32_t seq1, uint32_t seq2)
      {
        return (static_cast<int32_t>(seq1 - seq2) > 0);
      }

      inline bool stream::greater_or_equal_than(uint32_t seq1, uint32_t seq2)
      {
        return (static_cast<int32_t>(seq1 - seq2) >= 0);
      }

      inline bool stream::equal(uint32_t seq1, uint32_t seq2)
      {
        return (seq1 == seq2);
      }
    }
  }
}

#endif // NET_IP_TCP_STREAM_H
