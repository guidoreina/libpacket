#include "net/ip/tcp/connection.h"
#include "net/ip/tcp/flags.h"

bool net::ip::tcp::connection::process(direction dir,
                                       uint8_t flags,
                                       state& s,
                                       originator& active_closer)
{
  // http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf

  switch (s) {
    case state::connection_requested:
      switch (flags & flag_mask) {
        case syn | ack:
          if (dir == direction::from_server) {
            s = state::connection_established;
            return true;
          }

          break;
        case syn:
        case ack:
          // Retransmission / out-of-order?
          if (dir == direction::from_client) {
            return true;
          }

          break;
        case rst:
        case rst | ack:
          s = state::closed;

          active_closer = static_cast<originator>(dir);

          return true;
      }

      break;
    case state::connection_established:
      switch (flags & flag_mask) {
        case ack:
          if (dir == direction::from_client) {
            s = state::data_transfer;
            return true;
          }

          break;
        case syn:
          // Retransmission?
          if (dir == direction::from_client) {
            return true;
          }

          break;
        case syn | ack:
          // Retransmission?
          if (dir == direction::from_server) {
            return true;
          }

          break;
        case rst:
        case rst | ack:
          s = state::closed;

          active_closer = static_cast<originator>(dir);

          return true;
      }

      break;
    case state::data_transfer:
      switch (flags & flag_mask) {
        case ack:
          return true;
        case fin:
        case fin | ack:
          s = state::closing;

          active_closer = static_cast<originator>(dir);

          return true;
        case rst:
        case rst | ack:
          s = state::closed;

          active_closer = static_cast<originator>(dir);

          return true;
      }

      break;
    case state::closing:
      switch (flags & flag_mask) {
        case ack:
          return true;
        case fin:
        case fin | ack:
          if (static_cast<originator>(dir) != active_closer) {
            s = state::closed;
          }

          return true;
        case rst:
        case rst | ack:
          s = state::closed;
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
          return true;
      }

      break;
    case state::failure:
      return false;
  }

  s = state::failure;

  return false;
}
