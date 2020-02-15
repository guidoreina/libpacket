#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <inttypes.h>
#include "net/ip/services.h"
#include "pcap/ip/analyzer.h"
#include "net/ip/dns/message.h"

class services {
  public:
    // Constructor.
    services(const char* dirname);

    // Destructor.
    ~services();

    // Load services from directory.
    bool load(const char* dirname);

    // Add packet.
    bool add(const net::ip::packet& pkt);

    // Process DNS response (only if domains have been used).
    bool process_dns(const void* msg, size_t len);

  private:
    // Directory where to save the PCAP files.
    const char* const _M_directory;

    // Services.
    net::ip::services _M_services;

    // File.
    struct file {
      net::ip::service::identifier id;

      FILE* f;
    };

    // Files.
    file* _M_files = nullptr;
    size_t _M_size = 0;
    size_t _M_used = 0;

    // Add packet.
    bool add(net::ip::service::identifier id,
             const void* pkt,
             uint16_t pktlen,
             uint64_t timestamp);

    // Add PCAP file header.
    static void add_pcap_file_header(FILE* file);

    // Add packet.
    static void add(const void* pkt,
                    uint32_t pktlen,
                    uint64_t timestamp,
                    FILE* file);

    // Search.
    bool search(net::ip::service::identifier id, size_t& pos) const;

    // Allocate.
    bool allocate();

    // Disable copy constructor and assignment operator.
    services(const services&) = delete;
    services& operator=(const services&) = delete;
};

services::services(const char* dirname)
  : _M_directory(dirname)
{
}

services::~services()
{
  if (_M_files) {
    for (size_t i = _M_used; i > 0; i--) {
      fclose(_M_files[i - 1].f);
    }

    free(_M_files);
  }
}

bool services::load(const char* dirname)
{
  return _M_services.load(dirname);
}

bool services::add(const net::ip::packet& pkt)
{
  net::ip::service::identifier id;
  net::ip::service::direction dir;

  // IPv4?
  if (pkt.version() == net::ip::version::v4) {
    // TCP?
    if (pkt.is_tcp()) {
      if (_M_services.find(pkt.ipv4(), pkt.tcp(), id, dir)) {
        return add(id, pkt.ipv4(), pkt.length(), pkt.timestamp());
      }
    } else if (pkt.is_udp()) {
      if (_M_services.find(pkt.ipv4(), pkt.udp(), id, dir)) {
        return add(id, pkt.ipv4(), pkt.length(), pkt.timestamp());
      }
    }
  } else {
    // TCP?
    if (pkt.is_tcp()) {
      if (_M_services.find(pkt.ipv6(), pkt.tcp(), id, dir)) {
        return add(id, pkt.ipv6(), pkt.length(), pkt.timestamp());
      }
    } else if (pkt.is_udp()) {
      if (_M_services.find(pkt.ipv6(), pkt.udp(), id, dir)) {
        return add(id, pkt.ipv6(), pkt.length(), pkt.timestamp());
      }
    }
  }

  return true;
}

bool services::process_dns(const void* msg, size_t len)
{
  return _M_services.process_dns(msg, len);
}

bool services::add(net::ip::service::identifier id,
                   const void* pkt,
                   uint16_t pktlen,
                   uint64_t timestamp)
{
  // Search service.
  size_t pos;
  if (search(id, pos)) {
    add(pkt, pktlen, timestamp, _M_files[pos].f);
    return true;
  } else {
    // Get service name.
    const char* const name = _M_services.name(id);
    if (name) {
      char filename[PATH_MAX];
      snprintf(filename, sizeof(filename), "%s/%s.pcap", _M_directory, name);

      // Open PCAP file for writing.
      FILE* f = fopen(filename, "w");

      // If the PCAP file could be opened...
      if (f) {
        if (allocate()) {
          // If not the last file...
          if (pos < _M_used) {
            memmove(&_M_files[pos + 1],
                    &_M_files[pos],
                    (_M_used - pos) * sizeof(file));
          }

          _M_files[pos].id = id;
          _M_files[pos].f = f;

          _M_used++;

          // Add PCAP file header.
          add_pcap_file_header(f);

          // Add packet.
          add(pkt, pktlen, timestamp, f);

          return true;
        }

        fclose(f);

        unlink(filename);
      }

      return false;
    }

    return true;
  }
}

void services::add_pcap_file_header(FILE* file)
{
  static const uint8_t header[] = {
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x65, 0x00, 0x00, 0x00
  };

  fwrite(header, 1, sizeof(header), file);
}

void services::add(const void* pkt,
                   uint32_t pktlen,
                   uint64_t timestamp,
                   FILE* file)
{
  const uint32_t sec = timestamp / 1000000ull;
  const uint32_t usec = timestamp % 1000000ull;

  fwrite(&sec, 1, 4, file);
  fwrite(&usec, 1, 4, file);

  fwrite(&pktlen, 1, 4, file);
  fwrite(&pktlen, 1, 4, file);

  fwrite(pkt, 1, pktlen, file);
}

bool services::search(net::ip::service::identifier id, size_t& pos) const
{
  ssize_t i = 0;
  ssize_t j = _M_used - 1;

  while (i <= j) {
    const ssize_t mid = (i + j) / 2;

    if (id < _M_files[mid].id) {
      j = mid - 1;
    } else if (id > _M_files[mid].id) {
      i = mid + 1;
    } else {
      pos = static_cast<size_t>(mid);
      return true;
    }
  }

  pos = static_cast<size_t>(i);

  return false;
}

bool services::allocate()
{
  if (_M_used < _M_size) {
    return true;
  } else {
    const size_t size = (_M_size > 0) ? _M_size * 2 : 64;

    file* files = static_cast<file*>(realloc(_M_files, size * sizeof(file)));
    if (files) {
      _M_files = files;
      _M_size = size;

      return true;
    } else {
      return false;
    }
  }
}

int main(int argc, const char** argv)
{
  if (argc == 4) {
    struct stat sbuf;
    if ((stat(argv[3], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
      // Load services.
      services services(argv[3]);
      if (services.load(argv[1])) {
        // Open PCAP file.
        pcap::ip::analyzer analyzer;
        if (analyzer.open(argv[2])) {
          pcap::ip::analyzer::const_iterator it;
          if (analyzer.begin(it)) {
            uint64_t npkt = 0;

            do {
              npkt++;

              // TCP?
              if (it->is_tcp()) {
                // Add packet.
                if (!services.add(*it)) {
                  fprintf(stderr, "Error adding packet %" PRIu64 ".\n", npkt);
                  return false;
                }
              } else if (it->is_udp()) {
                // DNS response?
                if (it->udp()->source == net::ip::dns::port) {
                  // Process DNS message.
                  services.process_dns(it->l4(), it->l4length());
                } else {
                  // Add packet.
                  if (!services.add(*it)) {
                    fprintf(stderr, "Error adding packet %" PRIu64 ".\n", npkt);
                    return false;
                  }
                }
              }
            } while (analyzer.next(it));
          }

          return 0;
        } else {
          fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[2]);
        }
      }
    } else {
      fprintf(stderr, "'%s' doesn't exist or is not a directory.\n", argv[3]);
    }
  } else {
    fprintf(stderr,
            "Usage: %s <services-directory> <pcap-file> <output-directory>\n",
            argv[0]);
  }

  return -1;
}
