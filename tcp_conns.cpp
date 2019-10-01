#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "pcap/ip/tcp/connection/analyzer.h"

int main(int argc, const char** argv)
{
  if (argc == 2) {
    pcap::ip::analyzer analyzer;

    // Open PCAP file.
    if (analyzer.open(argv[1])) {
      // Read all packets.
      if (!analyzer.read_all()) {
        fprintf(stderr, "Error reading packets.\n");
        return -1;
      }

      pcap::ip::tcp::connection::analyzer conn_analyzer(analyzer);

      pcap::ip::tcp::connection::analyzer::const_iterator it;

      if (conn_analyzer.begin(it)) {
        size_t count = 0;

        do {
          count++;

          char client[INET6_ADDRSTRLEN + 8];
          it->client().to_string(client, sizeof(client));

          char server[INET6_ADDRSTRLEN + 8];
          it->server().to_string(server, sizeof(server));

          uint64_t syn_timestamp = it.syn()->timestamp();
          time_t t = syn_timestamp / 1000000ull;
          struct tm tmsyn;
          localtime_r(&t, &tmsyn);

          uint64_t syn_ack_timestamp = it.syn_ack()->timestamp();
          t = syn_ack_timestamp / 1000000ull;
          struct tm tmsyn_ack;
          localtime_r(&t, &tmsyn_ack);

          uint64_t ack_timestamp = it.ack()->timestamp();
          t = ack_timestamp / 1000000ull;
          struct tm tmack;
          localtime_r(&t, &tmack);

          printf("%s -> %s\n"
                 "        SYN: %04u/%02u/%02u %02u:%02u:%02u.%06u\n"
                 "  SYN + ACK: %04u/%02u/%02u %02u:%02u:%02u.%06u\n"
                 "        ACK: %04u/%02u/%02u %02u:%02u:%02u.%06u\n",
                 client,
                 server,
                 1900 + tmsyn.tm_year,
                 1 + tmsyn.tm_mon,
                 tmsyn.tm_mday,
                 tmsyn.tm_hour,
                 tmsyn.tm_min,
                 tmsyn.tm_sec,
                 static_cast<unsigned>(syn_timestamp % 1000000ull),
                 1900 + tmsyn_ack.tm_year,
                 1 + tmsyn_ack.tm_mon,
                 tmsyn_ack.tm_mday,
                 tmsyn_ack.tm_hour,
                 tmsyn_ack.tm_min,
                 tmsyn_ack.tm_sec,
                 static_cast<unsigned>(syn_ack_timestamp % 1000000ull),
                 1900 + tmack.tm_year,
                 1 + tmack.tm_mon,
                 tmack.tm_mday,
                 tmack.tm_hour,
                 tmack.tm_min,
                 tmack.tm_sec,
                 static_cast<unsigned>(ack_timestamp % 1000000ull));
        } while (conn_analyzer.next(it));

        printf("# connections: %zu.\n", count);
      } else {
        printf("No connections.\n");
      }

      return 0;
    } else {
      fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return -1;
}
