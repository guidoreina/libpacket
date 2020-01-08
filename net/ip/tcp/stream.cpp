#include "net/ip/tcp/stream.h"
#include "net/ip/tcp/flags.h"

net::ip::tcp::stream::beginstreamfn_t net::ip::tcp::stream::_M_beginstreamfn;
net::ip::tcp::stream::endstreamfn_t net::ip::tcp::stream::_M_endstreamfn;
net::ip::tcp::stream::payloadfn_t net::ip::tcp::stream::_M_payloadfn;
net::ip::tcp::stream::gapfn_t net::ip::tcp::stream::_M_gapfn;

void net::ip::tcp::stream::clear()
{
  while (_M_first) {
    segment* next = _M_first->next();

    _M_allocator.push(_M_first);

    _M_first = next;
  }

  _M_last = nullptr;

  _M_nsegments = 0;

  _M_offset = 0;

  _M_connection = nullptr;
  _M_user = nullptr;

  _M_ignore = false;
}

bool net::ip::tcp::stream::add(uint32_t seq,
                               uint8_t tcpflags,
                               const void* payload,
                               uint16_t payloadlen)
{
  // If the stream shouldn't be ignored...
  if (!_M_ignore) {
    // Is the SYN bit set?
    const bool synbit = (tcpflags & syn) != 0;

    // First packet of the stream?
    if (_M_connection->number_packets(_M_direction) == 1) {
      // Set next sequence number.
      _M_nxt = synbit ? seq + 1 : seq;
    }

    // If there is payload and the SYN bit is not set...
    if ((payloadlen > 0) && (!synbit)) {
      // If it is the next sequence number...
      if (equal(seq, _M_nxt)) {
        // Notify payload.
        return notify_payload(payload, payloadlen);
      } else if (less_than(seq, _M_nxt)) {
        // Old segment.

        // Check whether the segments overlap.
        if (greater_than(seq + payloadlen, _M_nxt)) {
          const uint32_t diff = _M_nxt - seq;

          payload = static_cast<const uint8_t*>(payload) + diff;
          payloadlen -= diff;

          // Notify payload.
          return notify_payload(payload, payloadlen);
        }

        // Old segment.
        return false;
      }

      // If there are already segments...
      if (_M_first) {
        // Search segment position starting from the end.
        segment* cur = _M_last;

        uint32_t nxt = seq + payloadlen;

        // While the sequence number of the new segment is smaller...
        while ((cur) && (less_than(seq, cur->seq()))) {
          // If the segments don't overlap...
          if (less_or_equal_than(nxt, cur->seq())) {
            cur = cur->prev();
          } else {
            payloadlen = cur->seq() - seq;
            nxt = cur->seq();

            cur = cur->prev();
          }
        }

        // If not the first segment...
        if (cur) {
          const uint32_t nxt = cur->seq() + cur->length();

          // If the segments don't overlap...
          if (less_or_equal_than(nxt, seq)) {
            // Insert segment after 'cur'.
            return insert(cur, seq, payload, payloadlen);
          } else if ((equal(seq, cur->seq())) &&
                     (payloadlen == cur->length())) {
            // Duplicated segment.
            return true;
          } else {
            const uint32_t diff = nxt - seq;

            if (diff < payloadlen) {
              payload = static_cast<const uint8_t*>(payload) + diff;
              payloadlen -= diff;

              // Insert segment after 'cur'.
              return insert(cur, seq, payload, payloadlen);
            }
          }
        } else {
          // First segment.

          // Get a free segment.
          segment* s = _M_allocator.pop();

          if (s) {
            // Initialize segment.
            if (s->init(seq, payload, payloadlen)) {
              s->prev(nullptr);
              s->next(_M_first);

              _M_first->prev(s);

              _M_first = s;

              // If there aren't too many queued segments...
              if (++_M_nsegments <= max_queued_segments) {
                return true;
              }

              // Notify gap and check segments.
              return ((notify_gap()) && (check_segments()));
            }

            // Return segment to the allocator.
            _M_allocator.push(s);
          }
        }
      } else {
        // First and only segment.

        // Get a free segment.
        segment* s = _M_allocator.pop();

        if (s) {
          // Initialize segment.
          if (s->init(seq, payload, payloadlen)) {
            s->prev(nullptr);
            s->next(nullptr);

            _M_first = s;
            _M_last = s;

            // Increment number of queued segments.
            _M_nsegments++;

            return true;
          }

          // Return segment to the allocator.
          _M_allocator.push(s);
        }
      }
    }
  }

  return false;
}

void net::ip::tcp::stream::terminate()
{
  // If the stream is active...
  if (_M_connection) {
    // If the stream shouldn't be ignored...
    if (!_M_ignore) {
      // Flush stream.
      flush();

      // Notify end of stream.
      _M_endstreamfn(_M_connection, _M_direction, _M_user);
    }

    // Clear stream.
    clear();
  }
}

bool net::ip::tcp::stream::notify_payload(const void* payload,
                                          uint16_t payloadlen)
{
  // Notify payload.
  if (_M_payloadfn(payload,
                   payloadlen,
                   _M_offset,
                   _M_connection,
                   _M_direction,
                   _M_user)) {
    // Increment next sequence number.
    _M_nxt += payloadlen;

    // Increment offset.
    _M_offset += payloadlen;

    // Check segments.
    return check_segments();
  } else {
    _M_ignore = true;
    return false;
  }
}

bool net::ip::tcp::stream::insert(segment* prev,
                                  uint32_t seq,
                                  const void* payload,
                                  uint16_t payloadlen)
{
  // Get a free segment.
  segment* s = _M_allocator.pop();

  if (s) {
    // Initialize segment.
    if (s->init(seq, payload, payloadlen)) {
      s->prev(prev);
      s->next(prev->next());

      // If not the last segment...
      if (s->next()) {
        s->next()->prev(s);
      } else {
        _M_last = s;
      }

      prev->next(s);

      // If there aren't too many queued segments...
      if (++_M_nsegments <= max_queued_segments) {
        return true;
      }

      // Notify gap and check segments.
      return ((notify_gap()) && (check_segments()));
    }

    // Return segment to the allocator.
    _M_allocator.push(s);
  }

  return false;
}

bool net::ip::tcp::stream::check_segments()
{
  // If there are queued segments...
  if (_M_first) {
    // Get rid of the old segments.
    while (_M_first->seq() <= _M_nxt) {
      // Save first segment.
      segment* first = _M_first;

      if (first->seq() == _M_nxt) {
        // Notify payload.
        if (_M_payloadfn(first->payload(),
                         first->length(),
                         _M_offset,
                         _M_connection,
                         _M_direction,
                         _M_user)) {
          // Increment next sequence number.
          _M_nxt += first->length();

          // Increment offset.
          _M_offset += first->length();
        } else {
          _M_ignore = true;
          return false;
        }
      }

      // Make '_M_first' point to the second segment.
      _M_first = first->next();

      // Free first segment.
      _M_allocator.push(first);

      // Decrement number of queued segments.
      _M_nsegments--;

      // If not the last segment...
      if (_M_first) {
        _M_first->prev(nullptr);
      } else {
        _M_last = nullptr;
        return true;
      }
    }
  }

  return true;
}

void net::ip::tcp::stream::flush()
{
  // While there are queued segments...
  while (_M_first) {
    // If there is a gap...
    if (_M_nxt != _M_first->seq()) {
      // Notify gap.
      notify_gap();
    }

    // Check segments.
    check_segments();
  }
}

bool net::ip::tcp::stream::notify_gap()
{
  // Compute gap size.
  const uint32_t gapsize = _M_first->seq() - _M_nxt;

  // Notify gap.
  if (_M_gapfn(gapsize, _M_offset, _M_connection, _M_direction, _M_user)) {
    // Set next sequence number.
    _M_nxt = _M_first->seq();

    // Increment offset.
    _M_offset += gapsize;

    return true;
  } else {
    _M_ignore = true;
    return false;
  }
}
