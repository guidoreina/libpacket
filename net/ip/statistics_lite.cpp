#include <stdlib.h>
#include <inttypes.h>
#include "net/ip/statistics_lite.h"
#include "net/ip/dns/message.h"

bool net::ip::statistics_lite::process(const struct iphdr* iphdr,
                                       const struct tcphdr* tcphdr,
                                       uint16_t pktlen,
                                       uint16_t l4len,
                                       uint64_t timestamp)
{
  // Add packet to the global statistics.
  _M_global_statistics.process(pktlen, l4len, timestamp);

  service::identifier id;
  service::direction dir;
  if (_M_services.find(iphdr, tcphdr, id, dir)) {
    return _M_statistics.process(dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

bool net::ip::statistics_lite::process(const struct iphdr* iphdr,
                                       const struct udphdr* udphdr,
                                       uint16_t pktlen,
                                       uint16_t l4len,
                                       uint64_t timestamp)
{
  // Add packet to the global statistics.
  _M_global_statistics.process(pktlen, l4len, timestamp);

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
    return _M_statistics.process(dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

bool net::ip::statistics_lite::process(const struct ip6_hdr* iphdr,
                                       const struct tcphdr* tcphdr,
                                       uint16_t pktlen,
                                       uint16_t l4len,
                                       uint64_t timestamp)
{
  // Add packet to the global statistics.
  _M_global_statistics.process(pktlen, l4len, timestamp);

  service::identifier id;
  service::direction dir;
  if (_M_services.find(iphdr, tcphdr, id, dir)) {
    return _M_statistics.process(dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

bool net::ip::statistics_lite::process(const struct ip6_hdr* iphdr,
                                       const struct udphdr* udphdr,
                                       uint16_t pktlen,
                                       uint16_t l4len,
                                       uint64_t timestamp)
{
  // Add packet to the global statistics.
  _M_global_statistics.process(pktlen, l4len, timestamp);

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
    return _M_statistics.process(dir, iphdr, pktlen, l4len, timestamp);
  }

  return true;
}

void net::ip::statistics_lite::print() const
{
  // Print global statistics.
  _M_global_statistics.print();

  // If the service was used...
  if (!_M_statistics.empty()) {
    printf("\nService:\n");

    // Print service statistics.
    _M_statistics.print(_M_global_statistics.transferred());
  }
}

void net::ip::statistics_lite::global_statistics::process(uint16_t pktlen,
                                                          uint16_t l4len,
                                                          uint64_t timestamp)
{
  // First packet?
  if (_M_timestamp_first_packet == 0) {
    _M_timestamp_first_packet = timestamp;
  }

  // Save timestamp of the last packet.
  _M_timestamp_last_packet = timestamp;

  _M_transferred.npackets++;
  _M_transferred.bytes += pktlen;
  _M_transferred.payload += l4len;
}

void net::ip::statistics_lite::global_statistics::print() const
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

  printf("Number of packets: %" PRIu64 ".\n", _M_transferred.npackets);

  printf("Total transferred: %" PRIu64 " bytes.\n", _M_transferred.bytes);

  printf("Total payload: %" PRIu64 " bytes (%.2f%%).\n",
         _M_transferred.payload,
         percentage(_M_transferred.payload, _M_transferred.bytes));
}

net::ip::statistics_lite::service_statistics::~service_statistics()
{
  // If the file has been opened...
  if (_M_csvfile) {
    // Dump statistics (if needed).
    dump(time(nullptr));

    // Close file.
    fclose(_M_csvfile);
  }
}

bool net::ip::statistics_lite::service_statistics::open(const char* filename)
{
  // Open file for appending.
  if ((_M_csvfile = fopen(filename, "a")) != nullptr) {
    // If the file is empty...
    if (ftell(_M_csvfile) == 0) {
      // Add CSV header.
      add_csv_header();
    }

    return true;
  }

  return false;
}

bool net::ip::statistics_lite::
service_statistics::process(service::direction dir,
                            const struct iphdr* iphdr,
                            uint16_t pktlen,
                            uint16_t l4len,
                            uint64_t timestamp)
{
  process(dir, pktlen, l4len, timestamp);

  // Download?
  if (dir == service::direction::download) {
    return _M_addresses.insert(iphdr->saddr);
  } else {
    return _M_addresses.insert(iphdr->daddr);
  }
}

bool net::ip::statistics_lite::
service_statistics::process(service::direction dir,
                            const struct ip6_hdr* iphdr,
                            uint16_t pktlen,
                            uint16_t l4len,
                            uint64_t timestamp)
{
  process(dir, pktlen, l4len, timestamp);

  // Download?
  if (dir == service::direction::download) {
    return _M_addresses.insert(iphdr->ip6_src);
  } else {
    return _M_addresses.insert(iphdr->ip6_dst);
  }
}

void net::ip::statistics_lite::service_statistics::dump(time_t t)
{
  // If the statistics should be dumped...
  if ((t != _M_timestamp) &&
      ((_M_upload.npackets != 0) || (_M_download.npackets != 0))) {
    add_line();

    // Clear statistics.
    _M_upload.clear();
    _M_download.clear();
    _M_addresses.clear();
  }
}

void net::ip::statistics_lite::
service_statistics::print(const transferred& transferred) const
{
  char s[32];
  printf("    Timestamp of the first packet: %s.\n",
         timestamp_to_string(_M_timestamp_first_packet, s, sizeof(s)));

  printf("    Timestamp of the last packet: %s.\n",
         timestamp_to_string(_M_timestamp_last_packet, s, sizeof(s)));

  printf("    Upload:\n");

  printf("      # packets: %" PRIu64 " (%.2f%%)\n",
         _M_total_upload.npackets,
         percentage(_M_total_upload.npackets, transferred.npackets));

  printf("      Bytes: %" PRIu64 " (%.2f%%)\n",
         _M_total_upload.bytes,
         percentage(_M_total_upload.bytes, transferred.bytes));

  printf("      Payload: %" PRIu64 " (%.2f%%)\n",
         _M_total_upload.payload,
         percentage(_M_total_upload.payload, transferred.payload));

  printf("    Download:\n");

  printf("      # packets: %" PRIu64 " (%.2f%%)\n",
         _M_total_download.npackets,
         percentage(_M_total_download.npackets, transferred.npackets));

  printf("      Bytes: %" PRIu64 " (%.2f%%)\n",
         _M_total_download.bytes,
         percentage(_M_total_download.bytes, transferred.bytes));

  printf("      Payload: %" PRIu64 " (%.2f%%)\n\n",
         _M_total_download.payload,
         percentage(_M_total_download.payload, transferred.payload));
}

void net::ip::statistics_lite::
service_statistics::process(service::direction dir,
                            uint16_t pktlen,
                            uint16_t l4len,
                            uint64_t timestamp)
{
  // First packet?
  if (_M_timestamp_first_packet == 0) {
    _M_timestamp_first_packet = timestamp;
  }

  // Save timestamp of the last packet.
  _M_timestamp_last_packet = timestamp;

  _M_timestamp = timestamp / 1000000ull;

  // Download?
  if (dir == service::direction::download) {
    _M_total_download.npackets++;
    _M_total_download.bytes += pktlen;
    _M_total_download.payload += l4len;

    _M_download.npackets++;
    _M_download.bytes += pktlen;
    _M_download.payload += l4len;
  } else {
    _M_total_upload.npackets++;
    _M_total_upload.bytes += pktlen;
    _M_total_upload.payload += l4len;

    _M_upload.npackets++;
    _M_upload.bytes += pktlen;
    _M_upload.payload += l4len;
  }
}

void net::ip::statistics_lite::service_statistics::add_csv_header()
{
  fprintf(_M_csvfile,
          "#timestamp%c"
          "packets-uploaded%c"
          "bytes-uploaded%c"
          "payload-uploaded%c"
          "packets-downloaded%c"
          "bytes-downloaded%c"
          "payload-downloaded%c"
          "ip-addresses\n",
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator,
          csv_separator);
}

void net::ip::statistics_lite::service_statistics::add_line()
{
  const char* addresses = _M_addresses.to_string();
  if (!addresses) {
    addresses = "";
  }

  char s[32];
  fprintf(_M_csvfile,
          "%s%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%" PRIu64 "%c"
          "%s\n",
          timestamp_to_string(_M_timestamp, s, sizeof(s)),
          csv_separator,
          _M_upload.npackets,
          csv_separator,
          _M_upload.bytes,
          csv_separator,
          _M_upload.payload,
          csv_separator,
          _M_download.npackets,
          csv_separator,
          _M_download.bytes,
          csv_separator,
          _M_download.payload,
          csv_separator,
          addresses);
}

const char* net::ip::statistics_lite::timestamp_to_string(uint64_t timestamp,
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

const char* net::ip::statistics_lite::timestamp_to_string(time_t timestamp,
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
