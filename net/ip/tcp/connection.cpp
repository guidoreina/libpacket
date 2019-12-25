#include "net/ip/tcp/connection.h"
#include "net/ip/tcp/flags.h"

uint64_t net::ip::tcp::connection::time_wait = 2 * 60 * 1000000ull;

bool net::ip::tcp::connection::process(direction dir,
                                       uint8_t flags,
                                       uint64_t timestamp)
{
  // Increment number of sent packets.
  _M_npackets[static_cast<size_t>(dir)]++;

  // http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf

  switch (_M_state) {
    case state::connection_requested:
      switch (flags & flag_mask) {
        case syn | ack:
          if (dir == direction::from_server) {
            _M_state = state::connection_established;

            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
        case syn:
        case ack:
          // Retransmission / out-of-order?
          if (dir == direction::from_client) {
            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
        case rst:
        case rst | ack:
          _M_state = state::closed;

          _M_active_closer = static_cast<originator>(dir);

          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
      }

      break;
    case state::connection_established:
      switch (flags & flag_mask) {
        case ack:
          if (dir == direction::from_client) {
            _M_state = state::data_transfer;

            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
        case syn:
          // Retransmission?
          if (dir == direction::from_client) {
            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
        case syn | ack:
          // Retransmission?
          if (dir == direction::from_server) {
            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
        case rst:
        case rst | ack:
          _M_state = state::closed;

          _M_active_closer = static_cast<originator>(dir);

          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
      }

      break;
    case state::data_transfer:
      switch (flags & flag_mask) {
        case ack:
          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
        case fin:
        case fin | ack:
          _M_state = state::closing;

          _M_active_closer = static_cast<originator>(dir);

          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
        case rst:
        case rst | ack:
          _M_state = state::closed;

          _M_active_closer = static_cast<originator>(dir);

          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
        case syn:
          // Retransmission?
          if ((dir == direction::from_client) &&
              (_M_timestamp.creation != 0) &&
              ((timestamp <= _M_timestamp.creation) ||
               (timestamp - _M_timestamp.creation <= time_wait))) {
            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
        case syn | ack:
          // Retransmission?
          if ((dir == direction::from_server) &&
              (_M_timestamp.creation != 0) &&
              ((timestamp <= _M_timestamp.creation) ||
               (timestamp - _M_timestamp.creation <= time_wait))) {
            // Update timestamp of the last packet.
            touch(timestamp);

            return true;
          }

          break;
      }

      break;
    case state::closing:
      switch (flags & flag_mask) {
        case ack:
          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
        case fin:
        case fin | ack:
          if (static_cast<originator>(dir) != _M_active_closer) {
            _M_state = state::closed;
          }

          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
        case rst:
        case rst | ack:
          _M_state = state::closed;

          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
      }

      break;
    case state::closed:
      switch (flags & flag_mask) {
        case ack:
        case fin:
        case fin | ack:
        case rst:
        case rst | ack:
          // Update timestamp of the last packet.
          touch(timestamp);

          return true;
      }

      break;
    case state::failure:
      return false;
  }

  _M_state = state::failure;

  return false;
}
