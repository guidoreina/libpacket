#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include "net/ip/statistics.h"
#include "net/ip/dns/message.h"

net::ip::statistics::~statistics()
{
  if (_M_statistics) {
    for (size_t i = _M_used; i > 0; i--) {
      service_statistics* const stats = &_M_statistics[i - 1];

      if (stats->csvfile) {
        // If some packet was sent or received lately...
        if ((stats->upload.npackets != 0) || (stats->download.npackets != 0)) {
          add(stats->timestamp, stats->upload, stats->download, stats->csvfile);
        }

        fclose(stats->csvfile);
      }

      if (stats->pcapfile) {
        fclose(stats->pcapfile);
      }
    }

    free(_M_statistics);
  }
}

bool net::ip::statistics::generate_csv_files(const char* dirname)
{
  const size_t len = strlen(dirname);

  if (len < sizeof(_M_csv_directory)) {
    memcpy(_M_csv_directory, dirname, len);
    _M_csv_directory[len] = 0;

    return true;
  }

  return false;
}

bool net::ip::statistics::generate_pcap_files(const char* dirname)
{
  const size_t len = strlen(dirname);

  if (len < sizeof(_M_pcap_directory)) {
    memcpy(_M_pcap_directory, dirname, len);
    _M_pcap_directory[len] = 0;

    return true;
  }

  return false;
}

bool net::ip::statistics::process(const struct iphdr* iphdr,
                                  const struct tcphdr* tcphdr,
                                  uint16_t pktlen,
                                  uint16_t l4len,
                                  uint64_t timestamp)
{
  // First packet?
  if (_M_timestamp_first_packet == 0) {
    _M_timestamp_first_packet = timestamp;
  }

  _M_timestamp_last_packet = timestamp;
  _M_npackets++;

  _M_ipv4++;
  _M_tcp++;

  _M_transferred += pktlen;
  _M_payload += l4len;

  service::identifier id;
  service::direction dir;
  if (_M_services.find(iphdr, tcphdr, id, dir)) {
    return process(id, dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

bool net::ip::statistics::process(const struct iphdr* iphdr,
                                  const struct udphdr* udphdr,
                                  uint16_t pktlen,
                                  uint16_t l4len,
                                  uint64_t timestamp)
{
  // First packet?
  if (_M_timestamp_first_packet == 0) {
    _M_timestamp_first_packet = timestamp;
  }

  _M_timestamp_last_packet = timestamp;
  _M_npackets++;

  _M_ipv4++;
  _M_udp++;

  _M_transferred += pktlen;
  _M_payload += l4len;

  // DNS response?
  if (udphdr->source == dns::port) {
    // Process DNS message.
    _M_services.process_dns(reinterpret_cast<const uint8_t*>(udphdr) +
                            sizeof(struct udphdr),
                            l4len);
  }

  service::identifier id;
  service::direction dir;
  if (_M_services.find(iphdr, udphdr, id, dir)) {
    return process(id, dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

bool net::ip::statistics::process(const struct ip6_hdr* iphdr,
                                  const struct tcphdr* tcphdr,
                                  uint16_t pktlen,
                                  uint16_t l4len,
                                  uint64_t timestamp)
{
  // First packet?
  if (_M_timestamp_first_packet == 0) {
    _M_timestamp_first_packet = timestamp;
  }

  _M_timestamp_last_packet = timestamp;
  _M_npackets++;

  _M_ipv6++;
  _M_tcp++;

  _M_transferred += pktlen;
  _M_payload += l4len;

  service::identifier id;
  service::direction dir;
  if (_M_services.find(iphdr, tcphdr, id, dir)) {
    return process(id, dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

bool net::ip::statistics::process(const struct ip6_hdr* iphdr,
                                  const struct udphdr* udphdr,
                                  uint16_t pktlen,
                                  uint16_t l4len,
                                  uint64_t timestamp)
{
  // First packet?
  if (_M_timestamp_first_packet == 0) {
    _M_timestamp_first_packet = timestamp;
  }

  _M_timestamp_last_packet = timestamp;
  _M_npackets++;

  _M_ipv6++;
  _M_udp++;

  _M_transferred += pktlen;
  _M_payload += l4len;

  // DNS response?
  if (udphdr->source == dns::port) {
    // Process DNS message.
    _M_services.process_dns(reinterpret_cast<const uint8_t*>(udphdr) +
                            sizeof(struct udphdr),
                            l4len);
  }

  service::identifier id;
  service::direction dir;
  if (_M_services.find(iphdr, udphdr, id, dir)) {
    return process(id, dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

void net::ip::statistics::print() const
{
  printf("########################################\n");
  printf("########################################\n");
  printf("##                                    ##\n");
  printf("## TCP and UDP statistics.            ##\n");
  printf("##                                    ##\n");
  printf("########################################\n");
  printf("########################################\n\n");

  char s[32];
  printf("Timestamp of the first packet: %s.\n",
         timestamp_to_string(_M_timestamp_first_packet, s, sizeof(s)));

  printf("Timestamp of the last packet: %s.\n",
         timestamp_to_string(_M_timestamp_last_packet, s, sizeof(s)));

  printf("Number of packets: %" PRIu64 ".\n", _M_npackets);

  printf("Number of IPv4 packets: %" PRIu64 " (%.2f%%).\n",
         _M_ipv4,
         percentage(_M_ipv4, _M_npackets));

  printf("Number of IPv6 packets: %" PRIu64 " (%.2f%%).\n",
         _M_ipv6,
         percentage(_M_ipv6, _M_npackets));

  printf("Number of TCP segments: %" PRIu64 " (%.2f%%).\n",
         _M_tcp,
         percentage(_M_tcp, _M_npackets));

  printf("Number of UDP datagrams: %" PRIu64 " (%.2f%%).\n",
         _M_udp,
         percentage(_M_udp, _M_npackets));

  printf("Total transferred: %" PRIu64 " bytes.\n", _M_transferred);

  printf("Total payload: %" PRIu64 " bytes (%.2f%%).\n",
         _M_payload,
         percentage(_M_payload, _M_transferred));

  printf("\nServices:\n");

  // For each service...
  for (size_t i = _M_used; i > 0; i--) {
    const service_statistics* const stats = &_M_statistics[i - 1];

    printf("  %s:\n", _M_services.name(stats->id));

    printf("    Timestamp of the first packet: %s.\n",
           timestamp_to_string(stats->timestamp_first_packet, s, sizeof(s)));

    printf("    Timestamp of the last packet: %s.\n",
           timestamp_to_string(stats->timestamp_last_packet, s, sizeof(s)));

    printf("    Upload:\n");

    printf("      # packets: %" PRIu64 " (%.2f%%)\n",
           stats->total_upload.npackets,
           percentage(stats->total_upload.npackets, _M_npackets));

    printf("      Bytes: %" PRIu64 " (%.2f%%)\n",
           stats->total_upload.bytes,
           percentage(stats->total_upload.bytes, _M_transferred));

    printf("      Payload: %" PRIu64 " (%.2f%%)\n",
           stats->total_upload.payload,
           percentage(stats->total_upload.payload, _M_payload));

    printf("    Download:\n");

    printf("      # packets: %" PRIu64 " (%.2f%%)\n",
           stats->total_download.npackets,
           percentage(stats->total_download.npackets, _M_npackets));

    printf("      Bytes: %" PRIu64 " (%.2f%%)\n",
           stats->total_download.bytes,
           percentage(stats->total_download.bytes, _M_transferred));

    printf("      Payload: %" PRIu64 " (%.2f%%)\n\n",
           stats->total_download.payload,
           percentage(stats->total_download.payload, _M_payload));
  }
}

bool net::ip::statistics::process(service::identifier id,
                                  service::direction dir,
                                  const void* pkt,
                                  uint16_t pktlen,
                                  uint16_t l4len,
                                  uint64_t timestamp)
{
  // Find service.
  size_t pos;
  if (find(id, pos)) {
    service_statistics* const stats = &_M_statistics[pos];

    stats->timestamp_last_packet = timestamp;

    const time_t sec = timestamp / 1000000ull;

    if ((stats->csvfile) && (sec != stats->timestamp)) {
      add(stats->timestamp, stats->upload, stats->download, stats->csvfile);

      stats->upload.clear();
      stats->download.clear();
    }

    stats->timestamp = sec;

    // Download?
    if (dir == service::direction::download) {
      stats->total_download.npackets++;
      stats->total_download.bytes += pktlen;
      stats->total_download.payload += l4len;

      if (stats->csvfile) {
        stats->download.npackets++;
        stats->download.bytes += pktlen;
        stats->download.payload += l4len;
      }
    } else {
      stats->total_upload.npackets++;
      stats->total_upload.bytes += pktlen;
      stats->total_upload.payload += l4len;

      if (stats->csvfile) {
        stats->upload.npackets++;
        stats->upload.bytes += pktlen;
        stats->upload.payload += l4len;
      }
    }

    if (stats->pcapfile) {
      // Add packet to the PCAP file.
      add(pkt, pktlen, timestamp, stats->pcapfile);
    }

    return true;
  } else {
    FILE* csvfile = nullptr;
    FILE* pcapfile = nullptr;

    char csvfilename[PATH_MAX + 32];
    char pcapfilename[PATH_MAX + 32];

    if ((*_M_csv_directory) || (*_M_pcap_directory)) {
      // Get service name.
      const char* const name = _M_services.name(id);
      if (name) {
        if (*_M_csv_directory) {
          snprintf(csvfilename,
                   sizeof(csvfilename),
                   "%s/%s.csv",
                   _M_csv_directory,
                   name);

          if ((csvfile = fopen(csvfilename, "w")) != nullptr) {
            // Add CSV header.
            add_csv_header(csvfile);
          } else {
            return false;
          }
        }

        if (*_M_pcap_directory) {
          snprintf(pcapfilename,
                   sizeof(pcapfilename),
                   "%s/%s.pcap",
                   _M_pcap_directory,
                   name);

          if ((pcapfile = fopen(pcapfilename, "w")) != nullptr) {
            // Add PCAP file header.
            add_pcap_file_header(pcapfile);

            // Add packet to the PCAP file.
            add(pkt, pktlen, timestamp, pcapfile);
          } else {
            return false;
          }
        }
      } else {
        return false;
      }
    }

    if (allocate()) {
      // If not the last service statistics...
      if (pos < _M_used) {
        memmove(&_M_statistics[pos + 1],
                &_M_statistics[pos],
                (_M_used - pos) * sizeof(service_statistics));
      }

      service_statistics* const stats = &_M_statistics[pos];

      stats->id = id;
      stats->timestamp_first_packet = timestamp;
      stats->timestamp_last_packet = timestamp;

      stats->timestamp = timestamp / 1000000ull;

      if (dir == service::direction::upload) {
        stats->total_upload.npackets = 1;
        stats->total_upload.bytes = pktlen;
        stats->total_upload.payload = l4len;

        stats->total_download.clear();
        stats->download.clear();

        if (csvfile) {
          stats->upload.npackets = 1;
          stats->upload.bytes = pktlen;
          stats->upload.payload = l4len;
        } else {
          stats->upload.clear();
        }
      } else {
        stats->total_download.npackets = 1;
        stats->total_download.bytes = pktlen;
        stats->total_download.payload = l4len;

        stats->total_upload.clear();
        stats->upload.clear();

        if (csvfile) {
          stats->download.npackets = 1;
          stats->download.bytes = pktlen;
          stats->download.payload = l4len;
        } else {
          stats->download.clear();
        }
      }

      stats->csvfile = csvfile;
      stats->pcapfile = pcapfile;

      _M_used++;

      return true;
    } else {
      if (csvfile) {
        fclose(csvfile);
        unlink(csvfilename);
      }

      if (pcapfile) {
        fclose(pcapfile);
        unlink(pcapfilename);
      }

      return false;
    }
  }
}

bool net::ip::statistics::find(service::identifier id, size_t& pos) const
{
  ssize_t i = 0;
  ssize_t j = _M_used - 1;

  while (i <= j) {
    const ssize_t mid = (i + j) / 2;

    if (id < _M_statistics[mid].id) {
      j = mid - 1;
    } else if (id > _M_statistics[mid].id) {
      i = mid + 1;
    } else {
      pos = static_cast<size_t>(mid);
      return true;
    }
  }

  pos = static_cast<size_t>(i);

  return false;
}

bool net::ip::statistics::allocate()
{
  if (_M_used < _M_size) {
    return true;
  } else {
    const size_t size = (_M_size > 0) ? _M_size * 2 : allocation;

    service_statistics*
      tmpstatistics = static_cast<service_statistics*>(
                        realloc(_M_statistics,
                                size * sizeof(service_statistics))
                      );

    if (tmpstatistics) {
      _M_statistics = tmpstatistics;
      _M_size = size;

      return true;
    } else {
      return false;
    }
  }
}

void net::ip::statistics::add_csv_header(FILE* file)
{
  fprintf(file,
          "#timestamp%c"
          "packets-uploaded%c"
          "bytes-uploaded%c"
          "payload-uploaded%c"
          "packets-downloaded%c"
          "bytes-downloaded%c"
          "payload-downloaded\n",
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator);
}

void net::ip::statistics::add(time_t timestamp,
                              const transferred& upload,
                              const transferred& download,
                              FILE* file)
{
  char s[32];
  fprintf(file,
          "%s%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "\n",
          timestamp_to_string(timestamp, s, sizeof(s)),
          csv_separator,
          upload.npackets,
          csv_separator,
          upload.bytes,
          csv_separator,
          upload.payload,
          csv_separator,
          download.npackets,
          csv_separator,
          download.bytes,
          csv_separator,
          download.payload);
}

void net::ip::statistics::add_pcap_file_header(FILE* file)
{
  static const uint8_t header[] = {
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x65, 0x00, 0x00, 0x00
  };

  fwrite(header, 1, sizeof(header), file);
}

void net::ip::statistics::add(const void* pkt,
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

const char* net::ip::statistics::timestamp_to_string(uint64_t timestamp,
                                                     char* s,
                                                     size_t n)
{
  const time_t t = timestamp / 1000000ull;
  struct tm tm;
  localtime_r(&t, &tm);

  snprintf(s,
           n,
           "%04u/%02u/%02u %02u:%02u:%02u.%06u",
           1900 + tm.tm_year,
           1 + tm.tm_mon,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           static_cast<unsigned>(timestamp % 1000000ull));

  return s;
}

const char* net::ip::statistics::timestamp_to_string(time_t timestamp,
                                                     char* s,
                                                     size_t n)
{
  struct tm tm;
  localtime_r(&timestamp, &tm);

  snprintf(s,
           n,
           "%04u/%02u/%02u %02u:%02u:%02u",
           1900 + tm.tm_year,
           1 + tm.tm_mon,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec);

  return s;
}
