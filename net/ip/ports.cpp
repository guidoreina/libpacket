#include <stdio.h>
#include "net/ip/ports.h"

bool net::ip::ports::build(const char* s)
{
  if ((s) && (*s)) {
    if (init()) {
      unsigned first_port = 0;
      unsigned last_port = 0;

      int state = 0; // Initial state.

      do {
        switch (state) {
          case 0: // Initial state.
            if ((*s >= '0') && (*s <= '9')) {
              first_port = *s - '0';

              state = 1; // Parsing first port.
            } else if (*s == '-') {
              first_port = 0;

              state = 3; // Parsing range.
            } else if ((*s != ' ') && (*s != '\t')) {
              return false;
            }

            break;
          case 1: // Parsing first port.
            if ((*s >= '0') && (*s <= '9')) {
              if ((first_port = (first_port * 10) + (*s - '0')) > 65535) {
                return false;
              }
            } else if (*s == separator) {
              _M_ports[first_port] = true;

              state = 6; // After separator.
            } else if (*s == '-') {
              state = 3; // Parsing range.
            } else if ((*s == ' ') || (*s == '\t')) {
              state = 2; // Space after first port.
            }

            break;
          case 2: // Space after first port.
            switch (*s) {
              case separator:
                _M_ports[first_port] = true;

                state = 6; // After separator.
                break;
              case '-':
                state = 3; // Parsing range.
                break;
              case ' ':
              case '\t':
                break;
              default:
                return false;
            }

            break;
          case 3: // Parsing range.
            if ((*s >= '0') && (*s <= '9')) {
              last_port = *s - '0';

              state = 4; // Parsing second port.
            } else if (*s == separator) {
              for (size_t i = first_port; i < max_ports; i++) {
                _M_ports[i] = true;
              }

              state = 6; // After separator.
            } else if ((*s != ' ') && (*s != '\t')) {
              return false;
            }

            break;
          case 4: // Parsing second port.
            if ((*s >= '0') && (*s <= '9')) {
              if ((last_port = (last_port * 10) + (*s - '0')) > 65535) {
                return false;
              }
            } else if (*s == separator) {
              if (first_port <= last_port) {
                for (unsigned i = first_port; i <= last_port; i++) {
                  _M_ports[i] = true;
                }

                state = 6; // After separator.
              } else {
                return false;
              }
            } else if ((*s == ' ') || (*s == '\t')) {
              state = 5; // Space after second port.
            } else {
              return false;
            }

            break;
          case 5: // Space after second port.
            switch (*s) {
              case separator:
                if (first_port <= last_port) {
                  for (unsigned i = first_port; i <= last_port; i++) {
                    _M_ports[i] = true;
                  }

                  state = 6; // After separator.
                } else {
                  return false;
                }

                break;
              case ' ':
              case '\t':
                break;
              default:
                return false;
            }

            break;
          case 6: // After separator.
            if ((*s >= '0') && (*s <= '9')) {
              first_port = *s - '0';

              state = 1; // Parsing first port.
            } else if (*s == '-') {
              first_port = 0;

              state = 3; // Parsing range.
            } else if ((*s != ' ') && (*s != '\t')) {
              return false;
            }

            break;
        }
      } while (*++s);

      switch (state) {
        case 0: // Initial state.
          for (size_t i = max_ports; i > 0; i--) {
            _M_ports[i - 1] = true;
          }

          break;
        case 1: // Parsing first port.
        case 2: // Space after first port.
          _M_ports[first_port] = true;
          break;
        case 3: // Parsing range.
          for (size_t i = first_port; i < max_ports; i++) {
            _M_ports[i] = true;
          }

          break;
        case 4: // Parsing second port.
        case 5: // Space after second port.
          if (first_port <= last_port) {
            for (unsigned i = first_port; i <= last_port; i++) {
              _M_ports[i] = true;
            }
          } else {
            return false;
          }

          break;
        case 6: // After separator.
          return false;
      }

      return true;
    }

    return false;
  }

  return true;
}

void net::ip::ports::print() const
{
  if (_M_ports) {
    ssize_t first_port = -1;
    ssize_t last_port = -1;

    for (size_t i = 0; i < max_ports; i++) {
      if (_M_ports[i]) {
        if (first_port < 0) {
          first_port = i;
        }

        last_port = i;
      } else {
        if (first_port != -1) {
          if (first_port != last_port) {
            printf("%zd-%zd\n", first_port, last_port);
          } else {
            printf("%zd\n", first_port);
          }

          first_port = -1;
        }
      }
    }

    if (first_port != -1) {
      if (first_port != last_port) {
        printf("%zd-%zd\n", first_port, last_port);
      } else {
        printf("%zd\n", first_port);
      }
    }
  } else {
    printf("0-%zu\n", max_ports - 1);
  }
}

bool net::ip::ports::add(in_port_t port, bool val)
{
  if ((_M_ports) || (init())) {
    _M_ports[port] = val;
    return true;
  } else {
    return false;
  }
}

bool net::ip::ports::add(in_port_t first_port, in_port_t last_port, bool val)
{
  if ((_M_ports) || (init())) {
    for (unsigned i = first_port; i <= last_port; i++) {
      _M_ports[i] = val;
    }

    return true;
  } else {
    return false;
  }
}

bool net::ip::ports::init()
{
  if ((_M_ports = static_cast<bool*>(
                    malloc(max_ports * sizeof(bool))
                  )) != nullptr) {
    for (size_t i = max_ports; i > 0; i--) {
      _M_ports[i - 1] = false;
    }

    return true;
  }

  return false;
}
