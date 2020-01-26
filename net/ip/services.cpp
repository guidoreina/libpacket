#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include "net/ip/services.h"
#include "net/ip/dns/message.h"
#include "net/ip/limits.h"

net::ip::services::~services()
{
  if (_M_services) {
    for (size_t i = _M_used; i > 0; i--) {
      free(_M_services[i - 1].name);
    }

    free(_M_services);
  }
}

bool net::ip::services::load(const char* dirname)
{
  // Open directory.
  DIR* dir = opendir(dirname);

  // If the directory could be opened...
  if (dir) {
    // For each directory entry...
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
      // If neither the current directory nor the parent directory...
      if ((strcmp(entry->d_name, ".") != 0) &&
          (strcmp(entry->d_name, "..") != 0)) {
        // Find last dot.
        char* const last_dot = strrchr(entry->d_name, '.');

        // Service?
        if ((last_dot) && (strcmp(last_dot + 1, service::extension) == 0)) {
          // Extract service id from the filename.
          service::identifier id = 0;
          const char* ptr = entry->d_name;
          while ((*ptr) && (*ptr != '_')) {
            // Digit?
            if ((*ptr >= '0') && (*ptr <= '9')) {
              const service::identifier tmpid = (id * 10) + (*ptr - '0');
              if (tmpid >= id) {
                id = tmpid;
                ptr++;
              } else {
                // Overflow.
                fprintf(stderr,
                        "Service id is too big (filename: '%s').\n",
                        entry->d_name);

                closedir(dir);

                return false;
              }
            } else {
              fprintf(stderr,
                      "Invalid service id (filename: '%s').\n",
                      entry->d_name);

              fprintf(stderr,
                      "Format: <service-id>_<service-name>.%s\n",
                      service::extension);

              closedir(dir);

              return false;
            }
          }

          // If neither the service id nor the service name is empty...
          if ((ptr != entry->d_name) && (++ptr != last_dot)) {
            // Compose path name.
            char pathname[PATH_MAX];
            snprintf(pathname,
                     sizeof(pathname),
                     "%s/%s",
                     dirname,
                     entry->d_name);

            // NULL-terminate service name.
            *last_dot = 0;

            // Load service.
            if (!load_service(id, ptr, last_dot - ptr, pathname)) {
              fprintf(stderr,
                      "Error loading service from file '%s'.\n",
                      pathname);

              closedir(dir);

              return false;
            }
          } else {
            fprintf(stderr,
                    "Service id or service name is empty (filename: '%s').\n",
                    entry->d_name);

            closedir(dir);

            return false;
          }
        }
      }
    }

    closedir(dir);

    return true;
  } else {
    fprintf(stderr, "Error opening directory '%s'.\n", dirname);
    return false;
  }
}

bool net::ip::services::process_dns(const void* msg, size_t len)
{
  // If no domains have been used...
  if (_M_domains.empty()) {
    return true;
  }

  // Parse DNS message.
  dns::message dnsmsg;
  if (dnsmsg.parse(msg, len)) {
    // Get domain.
    size_t domainlen;
    const char* domain = dnsmsg.domain(domainlen);

    // Make 'end' point to the end of the domain.
    const char* const end = domain + domainlen;

    do {
      // Find domain.
      const ports* const ports = _M_domains.find(domain);

      if (ports) {
        // For each response...
        const struct dns::message::response* response;
        for (size_t i = 0; (response = dnsmsg.response(i)) != nullptr; i++) {
          // IPv4?
          if (response->family == AF_INET) {
            if (!_M_addresses.insert(response->addr4, 32, *ports)) {
              return false;
            }
          } else {
            if (!_M_addresses.insert(response->addr6, 128, *ports)) {
              return false;
            }
          }
        }

        return true;
      } else {
        // Search next dot.
        const char* const dot =
          static_cast<const char*>(memchr(domain, '.', domainlen));

        if (dot) {
          domain = dot + 1;
          domainlen = end - domain;
        } else {
          return true;
        }
      }
    } while (true);
  }

  return false;
}

net::ip::services::domains::~domains()
{
  if (_M_domains) {
    for (size_t i = _M_used; i > 0; i--) {
      free(_M_domains[i - 1].name);
    }

    free(_M_domains);
  }
}

bool net::ip::services::domains::add(const char* name,
                                     size_t len,
                                     const ports& ports)
{
  // If the domain hasn't been added already...
  size_t pos;
  if (!find(name, pos)) {
    // Allocate domains (if needed).
    if (allocate()) {
      char* n = static_cast<char*>(malloc(len + 1));

      if (n) {
        memcpy(n, name, len);
        n[len] = 0;

        // If not the last domain...
        if (pos < _M_used) {
          memmove(&_M_domains[pos + 1],
                  &_M_domains[pos],
                  (_M_used - pos) * sizeof(domain));
        }

        _M_domains[pos].name = n;
        _M_domains[pos].ports = ports;

        _M_used++;

        return true;
      }
    }

    return false;
  }

  return true;
}

bool net::ip::services::domains::find(const char* name, size_t& pos) const
{
  ssize_t i = 0;
  ssize_t j = _M_used - 1;

  while (i <= j) {
    const ssize_t mid = (i + j) / 2;

    // Compare domains.
    const int ret = strcmp(name, _M_domains[mid].name);

    if (ret < 0) {
      j = mid - 1;
    } else if (ret > 0) {
      i = mid + 1;
    } else {
      pos = static_cast<size_t>(mid);
      return true;
    }
  }

  pos = static_cast<size_t>(i);

  return false;
}

bool net::ip::services::domains::allocate()
{
  if (_M_used < _M_size) {
    return true;
  } else {
    const size_t size = (_M_size > 0) ? _M_size * 2 : allocation;

    domain* tmpdomains = static_cast<domain*>(
                           realloc(_M_domains, size * sizeof(domain))
                         );

    if (tmpdomains) {
      _M_domains = tmpdomains;
      _M_size = size;

      return true;
    } else {
      return false;
    }
  }
}

bool net::ip::services::find(uint32_t saddr,
                             in_port_t sport,
                             uint32_t daddr,
                             in_port_t dport,
                             service::identifier& id,
                             service::direction& dir) const
{
  {
    const ports* const ports = _M_addresses.find(saddr);
    if (ports) {
      if ((sport >= ports->from_port) && (sport <= ports->to_port)) {
        id = ports->id;
        dir = service::direction::download;

        return true;
      } else {
        return false;
      }
    }
  }

  {
    const ports* const ports = _M_addresses.find(daddr);
    if (ports) {
      if ((dport >= ports->from_port) && (dport <= ports->to_port)) {
        id = ports->id;
        dir = service::direction::upload;

        return true;
      }
    }
  }

  return false;
}

bool net::ip::services::find(const struct in6_addr& saddr,
                             in_port_t sport,
                             const struct in6_addr& daddr,
                             in_port_t dport,
                             service::identifier& id,
                             service::direction& dir) const
{
  {
    const ports* const ports = _M_addresses.find(saddr);
    if (ports) {
      if ((sport >= ports->from_port) && (sport <= ports->to_port)) {
        id = ports->id;
        dir = service::direction::download;

        return true;
      } else {
        return false;
      }
    }
  }

  {
    const ports* const ports = _M_addresses.find(daddr);
    if (ports) {
      if ((dport >= ports->from_port) && (dport <= ports->to_port)) {
        id = ports->id;
        dir = service::direction::upload;

        return true;
      }
    }
  }

  return false;
}

bool net::ip::services::load_service(service::identifier id,
                                     const char* name,
                                     size_t len,
                                     const char* filename)
{
  // Open file for reading.
  FILE* file = fopen(filename, "r");

  // If the file could be opened...
  if (file) {
    // Add service.
    if (add(id, name, len)) {
      size_t nline = 0;

      // For each line...
      char line[1024];
      while (fgets(line, sizeof(line), file)) {
        nline++;

        // If the line is not commented out...
        if (line[0] != '#') {
          char* slash = nullptr;

          // Parse IP address / domain name.
          char* ptr = line;
          while ((*ptr > ' ') && (*ptr != separator)) {
            // If there is a prefix length...
            if (*ptr == '/') {
              slash = ptr++;

              break;
            }

            ptr++;
          }

          // If the IP address / domain name is not empty...
          if (ptr != line) {
            size_t prefixlen = 0;

            // If a slash has been found...
            if (slash) {
              // Parse prefix length.
              while ((*ptr > ' ') && (*ptr != separator)) {
                // Digit?
                if ((*ptr >= '0') && (*ptr <= '9')) {
                  if ((prefixlen = (prefixlen * 10) + (*ptr - '0')) <= 128) {
                    ptr++;
                  } else {
                    fprintf(stderr,
                            "Invalid prefix length (%s:%zu).\n",
                            filename,
                            nline);

                    fclose(file);
                    return false;
                  }
                } else {
                  fprintf(stderr,
                          "Invalid prefix length (%s:%zu).\n",
                          filename,
                          nline);

                  fclose(file);
                  return false;
                }
              }

              // If the prefix length is empty...
              if (slash + 1 == ptr) {
                fprintf(stderr,
                        "Prefix length is empty (%s:%zu).\n",
                        filename,
                        nline);

                fclose(file);
                return false;
              } else if (prefixlen == 0) {
                fprintf(stderr,
                        "Prefix length has to be bigger than 0 (%s:%zu).\n",
                        filename,
                        nline);

                fclose(file);
                return false;
              }

              // NULL-terminate IP address.
              *slash = 0;
            }

            // Save current character.
            const char c = *ptr;

            // NULL-terminate IP address / domain name.
            *ptr = 0;

            int family = AF_UNSPEC;

            uint32_t addr4;
            struct in6_addr addr6;

            char* domain = nullptr;
            size_t domainlen = 0;

            // IPv4?
            if (inet_pton(AF_INET, line, &addr4) == 1) {
              // If the prefix length is valid...
              if (prefixlen <= 32) {
                family = AF_INET;

                // If no prefix length has been defined...
                if (prefixlen == 0) {
                  prefixlen = 32;
                }
              } else {
                fprintf(stderr,
                        "Prefix length is too big (%s:%zu).\n",
                        filename,
                        nline);

                fclose(file);
                return false;
              }
            } else if (inet_pton(AF_INET6, line, &addr6) == 1) {
              family = AF_INET6;

              // If no prefix length has been defined...
              if (prefixlen == 0) {
                prefixlen = 128;
              }
            } else if (!slash) {
              const size_t len = ptr - line;

              // If the domain name is not too long...
              if (len <= domain_name_max_len) {
                if (line[0] == '*') {
                  if (line[1] == '.') {
                    if (len > 2) {
                      domain = line + 2;
                      domainlen = len - 2;
                    } else {
                      fprintf(stderr,
                              "Invalid IP address / domain name (%s:%zu).\n",
                              filename,
                              nline);

                      fclose(file);
                      return false;
                    }
                  } else if (len > 1) {
                    domain = line + 1;
                    domainlen = len - 1;
                  } else {
                    fprintf(stderr,
                            "Invalid IP address / domain name (%s:%zu).\n",
                            filename,
                            nline);

                    fclose(file);
                    return false;
                  }
                } else {
                  domain = line;
                  domainlen = len;
                }
              } else {
                fprintf(stderr,
                        "Domain name is too long (%s:%zu).\n",
                        filename,
                        nline);

                fclose(file);
                return false;
              }
            } else {
              fprintf(stderr,
                      "Invalid IP address / domain name (%s:%zu).\n",
                      filename,
                      nline);

              fclose(file);
              return false;
            }

            // Restore character.
            *ptr = c;

            ports ports;
            ports.from_port = 0;
            ports.to_port = 65535;

            // If there is from-port...
            if (c == separator) {
              const char* begin = ++ptr;

              // Parse from-port.
              unsigned port = 0;
              while ((*ptr > ' ') && (*ptr != separator)) {
                // Digit?
                if ((*ptr >= '0') && (*ptr <= '9')) {
                  if ((port = (port * 10) + (*ptr - '0')) <= 65535) {
                    ptr++;
                  } else {
                    fprintf(stderr,
                            "Invalid from-port (%s:%zu).\n",
                            filename,
                            nline);

                    fclose(file);
                    return false;
                  }
                } else {
                  fprintf(stderr,
                          "Invalid from-port (%s:%zu).\n",
                          filename,
                          nline);

                  fclose(file);
                  return false;
                }
              }

              // If the from-port is not empty...
              if (ptr != begin) {
                ports.from_port = static_cast<in_port_t>(port);

                // If there is to-port...
                if (*ptr == separator) {
                  begin = ++ptr;

                  // Parse to-port.
                  port = 0;
                  while (*ptr > ' ') {
                    // Digit?
                    if ((*ptr >= '0') && (*ptr <= '9')) {
                      if ((port = (port * 10) + (*ptr - '0')) <= 65535) {
                        ptr++;
                      } else {
                        fprintf(stderr,
                                "Invalid to-port (%s:%zu).\n",
                                filename,
                                nline);

                        fclose(file);
                        return false;
                      }
                    } else {
                      fprintf(stderr,
                              "Invalid to-port (%s:%zu).\n",
                              filename,
                              nline);

                      fclose(file);
                      return false;
                    }
                  }

                  // If the to-port is not empty...
                  if (ptr != begin) {
                    // If the from-port is less or equal than the to-port...
                    if (ports.from_port <= port) {
                      ports.to_port = static_cast<in_port_t>(port);
                    } else {
                      fprintf(stderr,
                              "from-port (%u) is greater than to-port (%u) "
                              "(%s:%zu).\n",
                              ports.from_port,
                              port,
                              filename,
                              nline);

                      fclose(file);
                      return false;
                    }
                  } else {
                    fprintf(stderr,
                            "to-port is empty (%s:%zu).\n",
                            filename,
                            nline);

                    fclose(file);
                    return false;
                  }
                }
              } else {
                fprintf(stderr,
                        "from-port is empty (%s:%zu).\n",
                        filename,
                        nline);

                fclose(file);
                return false;
              }
            }

            // Skip blanks (if any)...
            while ((*ptr == ' ') || (*ptr == '\t')) {
              ptr++;
            }

            // End of line?
            if ((!*ptr) || (*ptr == '\n') || (*ptr == '\r')) {
              ports.id = id;

              switch (family) {
                case AF_INET:
                  // Add IPv4 address.
                  if (!_M_addresses.insert(addr4, prefixlen, ports)) {
                    return false;
                  }

                  break;
                case AF_INET6:
                  // Add IPv6 address.
                  if (!_M_addresses.insert(addr6, prefixlen, ports)) {
                    return false;
                  }

                  break;
                default:
                  // Convert domain name to lowercase.
                  ptr = domain;
                  do {
                    *ptr = tolower(*ptr);
                  } while (*++ptr);

                  // Add domain.
                  if (!_M_domains.add(domain, domainlen, ports)) {
                    return false;
                  }
              }

              continue;
            }
          } else {
            // Skip blanks (if any)...
            while ((*ptr == ' ') || (*ptr == '\t')) {
              ptr++;
            }

            // If the line is empty...
            if ((!*ptr) || (*ptr == '\n') || (*ptr == '\r')) {
              continue;
            }
          }

          fprintf(stderr,
                  "Invalid characters (%s:%zu, column: %zu).\n",
                  filename,
                  nline,
                  ptr - line + 1);

          fclose(file);
          return false;
        }
      }

      fclose(file);

      return true;
    }

    fclose(file);
  } else {
    fprintf(stderr, "Error opening file '%s' for reading.\n", filename);
  }

  return false;
}

bool net::ip::services::add(service::identifier id,
                            const char* name,
                            size_t len)
{
  // If the service hasn't been added already...
  size_t pos;
  if (!find(id, pos)) {
    // Allocate services (if needed).
    if (allocate()) {
      char* n = static_cast<char*>(malloc(len + 1));

      if (n) {
        memcpy(n, name, len);
        n[len] = 0;

        // If not the last service...
        if (pos < _M_used) {
          memmove(&_M_services[pos + 1],
                  &_M_services[pos],
                  (_M_used - pos) * sizeof(service));
        }

        _M_services[pos].id = id;
        _M_services[pos].name = n;

        _M_used++;

        return true;
      }
    }
  } else {
    fprintf(stderr,
            "Cannot add service '%s' with service id %u, because the service "
            "id %u is already used by '%s'.\n",
            name,
            id,
            id,
            _M_services[pos].name);
  }

  return false;
}

bool net::ip::services::find(service::identifier id, size_t& pos) const
{
  ssize_t i = 0;
  ssize_t j = _M_used - 1;

  while (i <= j) {
    const ssize_t mid = (i + j) / 2;

    if (id < _M_services[mid].id) {
      j = mid - 1;
    } else if (id > _M_services[mid].id) {
      i = mid + 1;
    } else {
      pos = static_cast<size_t>(mid);
      return true;
    }
  }

  pos = static_cast<size_t>(i);

  return false;
}

bool net::ip::services::allocate()
{
  if (_M_used < _M_size) {
    return true;
  } else {
    const size_t size = (_M_size > 0) ? _M_size * 2 : allocation;

    service* tmpservices = static_cast<service*>(
                             realloc(_M_services, size * sizeof(service))
                           );

    if (tmpservices) {
      _M_services = tmpservices;
      _M_size = size;

      return true;
    } else {
      return false;
    }
  }
}
