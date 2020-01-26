#include <string.h>
#include <ctype.h>
#include "net/ip/dns/message.h"

bool net::ip::dns::message::parse(const void* buf, size_t len)
{
  // Save parameters.
  _M_buf = static_cast<const uint8_t*>(buf);
  _M_len = len;

  // If the DNS message should be processed...
  if ((_M_len >= header_len)           && // The message is not too short.
      (_M_len <= max_len)              && // The message is not too long.
      (((_M_buf[2] >> 3) & 0x0f) <= 2) && // 0 <= OPCODE <= 2
      ((_M_buf[2] & 0x02) == 0)        && // The message was not truncated.
      ((_M_buf[3] & 0x0f) == 0)) {        // RCODE = 0
    const uint16_t
      qdcount = (static_cast<uint16_t>(_M_buf[4]) << 8) | _M_buf[5];

    // If there are questions...
    if (qdcount > 0) {
      _M_off = header_len;

      // If the QNAME is valid and the QTYPE and QCLASS fit...
      if ((parse_domain_name()) && (_M_off + 4 <= _M_len)) {
        // If the QCLASS is 1 (IN [Internet])...
        if (((static_cast<uint16_t>(_M_buf[_M_off + 2]) << 8) |
             _M_buf[_M_off + 3]) == 1) {
          // Get QTYPE.
          const uint16_t qtype = (static_cast<uint16_t>(_M_buf[_M_off]) << 8) |
                                 _M_buf[_M_off + 1];

          if (qtype <= 255) {
            // Save query type.
            _M_qtype = static_cast<uint8_t>(qtype);

            // No responses so far.
            _M_nresponses = 0;

            // Query?
            if ((_M_buf[2] & 0x80) == 0) {
                return true;
            } else {
              const uint16_t ancount = (static_cast<uint16_t>(_M_buf[6]) << 8) |
                                       _M_buf[7];

              // If there are answers...
              if (ancount > 0) {
                // Skip QTYPE and QCLASS.
                _M_off += 4;

                // Skip following questions (if any).
                for (size_t i = 2; i <= qdcount; i++) {
                  if (!skip_question()) {
                    return false;
                  }
                }

                // Process answers.
                for (size_t i = 1; i <= ancount; i++) {
                  if ((skip_domain_name()) && (_M_off + 10 <= _M_len)) {
                    const uint16_t rdlength =
                      (static_cast<uint16_t>(_M_buf[_M_off + 8]) << 8) |
                      _M_buf[_M_off + 9];

                    const size_t next = _M_off + 10 + rdlength;
                    if (next <= _M_len) {
                      // If the CLASS is 1 (IN [Internet])...
                      if (((static_cast<uint16_t>(_M_buf[_M_off + 2]) << 8) |
                           _M_buf[_M_off + 3]) == 1) {
                        // Check type.
                        switch ((static_cast<uint16_t>(_M_buf[_M_off]) << 8) |
                                _M_buf[_M_off + 1]) {
                          case 1: // A (host address [IPv4]).
                            if (rdlength == 4) {
                              _M_responses[_M_nresponses].family = AF_INET;

                              memcpy(_M_responses[_M_nresponses].addr,
                                     _M_buf + _M_off + 10,
                                     4);

                              if (++_M_nresponses == max_responses) {
                                return true;
                              }
                            } else {
                              return false;
                            }

                            break;
                          case 28: // AAAA (IPv6).
                            if (rdlength == 16) {
                              _M_responses[_M_nresponses].family = AF_INET6;

                              memcpy(_M_responses[_M_nresponses].addr,
                                     _M_buf + _M_off + 10,
                                     16);

                              if (++_M_nresponses == max_responses) {
                                return true;
                              }
                            } else {
                              return false;
                            }

                            break;
                        }
                      }

                      _M_off = next;
                    } else {
                      return false;
                    }
                  } else {
                    return false;
                  }
                }

                return (_M_nresponses > 0);
              }
            }
          }
        }
      }
    }
  }

  return false;
}

bool net::ip::dns::message::parse_domain_name()
{
  size_t len = 0;
  size_t npointers = 0;

  // Work with a copy of the offset.
  size_t off = _M_off;

  while (off < _M_len) {
    switch (_M_buf[off] & 0xc0) {
      case 0: // Label.
        // If not the null label...
        if (_M_buf[off] > 0) {
          const size_t next = off + 1 + _M_buf[off];
          if ((next < _M_len) &&
              (len + 1 + _M_buf[off] <= domain_name_max_len)) {
            // If not the first label...
            if (len > 0) {
              _M_domain[len++] = '.';
            }

            // Convert label to lowercase.
            for (size_t i = 0; i < _M_buf[off]; i++) {
              _M_domain[len++] = tolower(_M_buf[off + 1 + i]);
            }

            off = next;
          } else {
            return false;
          }
        } else {
          // Null label.

          // If not the root domain name...
          if ((_M_domainlen = static_cast<uint8_t>(len)) > 0) {
            if (npointers == 0) {
              _M_off = off + 1;
            }

            _M_domain[len] = 0;

            return true;
          } else {
            return false;
          }
        }

        break;
      case 0xc0: // Pointer.
        if ((++npointers <= max_pointers) && (off + 1 < _M_len)) {
          // Compute pointer offset.
          const size_t
            ptroff = (static_cast<uint16_t>(_M_buf[off] & 0x3f) << 8) |
                     _M_buf[off + 1];

          // Valid offset?
          if ((ptroff >= header_len) && (ptroff < _M_len)) {
            // First pointer?
            if (npointers == 1) {
              _M_off = off + 2;
            }

            off = ptroff;
          } else {
            return false;
          }
        } else {
          return false;
        }

        break;
      default:
        return false;
    }
  }

  return false;
}

bool net::ip::dns::message::skip_domain_name()
{
  size_t len = 0;
  size_t npointers = 0;

  // Work with a copy of the offset.
  size_t off = _M_off;

  while (off < _M_len) {
    switch (_M_buf[off] & 0xc0) {
      case 0: // Label.
        // If not the null label...
        if (_M_buf[off] > 0) {
          const size_t next = off + 1 + _M_buf[off];
          if ((next < _M_len) &&
              (len + 1 + _M_buf[off] <= domain_name_max_len)) {
            // If not the first label...
            if (len > 0) {
              len += (1 + _M_buf[off]);
            } else {
              len += _M_buf[off];
            }

            off = next;
          } else {
            return false;
          }
        } else {
          // Null label.

          if (npointers == 0) {
            _M_off = off + 1;
          }

          return true;
        }

        break;
      case 0xc0: // Pointer.
        if ((++npointers <= max_pointers) && (off + 1 < _M_len)) {
          // Compute pointer offset.
          const size_t
            ptroff = (static_cast<uint16_t>(_M_buf[off] & 0x3f) << 8) |
                     _M_buf[off + 1];

          // Valid offset?
          if ((ptroff >= header_len) && (ptroff < _M_len)) {
            // First pointer?
            if (npointers == 1) {
              _M_off = off + 2;
            }

            off = ptroff;
          } else {
            return false;
          }
        } else {
          return false;
        }

        break;
      default:
        return false;
    }
  }

  return false;
}
