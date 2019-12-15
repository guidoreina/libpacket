#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "pcap/ip/analyzer.h"
#include "net/ip/tcp/connections.h"

int main(int argc, const char** argv)
{
  if (argc == 2) {
    // Open PCAP file.
    pcap::ip::analyzer analyzer;
    if (analyzer.open(argv[1])) {
      // Read all packets.
      if (!analyzer.read_all()) {
        fprintf(stderr, "Error reading packets.\n");
        return -1;
      }

      // Initialize connections.
      net::ip::tcp::connections conns;
      if (conns.init()) {
        pcap::ip::analyzer::const_iterator it;

        // Get first TCP segment.
        if (analyzer.begin(net::ip::protocol::tcp, it)) {
          size_t count = 0;

          do {
            // IPv4?
            const net::ip::tcp::connection* conn;
            if (it->version() == net::ip::version::v4) {
              // Process TCP segment.
              conn = conns.process(it->ipv4(), it->tcp(), it->timestamp());
            } else {
              // Process TCP segment.
              conn = conns.process(it->ipv6(), it->tcp(), it->timestamp());
            }

            if (conn) {
              count++;

              char client[INET6_ADDRSTRLEN + 8];
              conn->client().to_string(client, sizeof(client));

              char server[INET6_ADDRSTRLEN + 8];
              conn->server().to_string(server, sizeof(server));

              uint64_t creation_timestamp = conn->creation_timestamp();
              time_t t = creation_timestamp / 1000000ull;
              struct tm tmcreation;
              localtime_r(&t, &tmcreation);

              uint64_t last_timestamp = conn->last_timestamp();
              t = last_timestamp / 1000000ull;
              struct tm tmlast;
              localtime_r(&t, &tmlast);

              printf("%s -> %s\n"
                     "        Creation: %04u/%02u/%02u %02u:%02u:%02u.%06u\n"
                     "  Last timestamp: %04u/%02u/%02u %02u:%02u:%02u.%06u\n",
                     client,
                     server,
                     1900 + tmcreation.tm_year,
                     1 + tmcreation.tm_mon,
                     tmcreation.tm_mday,
                     tmcreation.tm_hour,
                     tmcreation.tm_min,
                     tmcreation.tm_sec,
                     static_cast<unsigned>(creation_timestamp % 1000000ull),
                     1900 + tmlast.tm_year,
                     1 + tmlast.tm_mon,
                     tmlast.tm_mday,
                     tmlast.tm_hour,
                     tmlast.tm_min,
                     tmlast.tm_sec,
                     static_cast<unsigned>(last_timestamp % 1000000ull));
            }
          } while (analyzer.next(net::ip::protocol::tcp, it));

          printf("# segments: %zu.\n", count);
        } else {
          printf("No TCP segments.\n");
        }

        return 0;
      } else {
        fprintf(stderr, "Error initializing TCP connections.\n");
      }
    } else {
      fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return -1;
}
