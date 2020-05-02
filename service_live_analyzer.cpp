#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "pcap/ip/live_analyzer.h"
#include "net/ip/statistics_lite.h"

static void signal_handler(int nsig);

static bool running = false;

int main(int argc, const char** argv)
{
  if (argc == 4) {
    // Load services.
    net::ip::statistics_lite statistics;
    if (statistics.load(argv[1])) {
      // Open PCAP file.
      pcap::ip::live_analyzer analyzer;
      if (analyzer.open(argv[2])) {
        // Open CSV file.
        if (statistics.open(argv[3])) {
          // Install signal handler.
          struct sigaction act;
          sigemptyset(&act.sa_mask);
          act.sa_flags = 0;
          act.sa_handler = signal_handler;
          sigaction(SIGTERM, &act, nullptr);
          sigaction(SIGINT, &act, nullptr);

          net::ip::packet pkt;

          running = true;

          do {
            // Read next packet.
            while (analyzer.read(pkt)) {
              // Dump statistics (if needed).
              statistics.dump(pkt.timestamp() / 1000000ull);

              // IPv4?
              if (pkt.version() == net::ip::version::v4) {
                // TCP?
                if (pkt.is_tcp()) {
                  statistics.process(pkt.ipv4(),
                                     pkt.tcp(),
                                     pkt.length(),
                                     pkt.l4length(),
                                     pkt.timestamp());
                } else if (pkt.is_udp()) {
                  statistics.process(pkt.ipv4(),
                                     pkt.udp(),
                                     pkt.length(),
                                     pkt.l4length(),
                                     pkt.timestamp());
                }
              } else {
                // TCP?
                if (pkt.is_tcp()) {
                  statistics.process(pkt.ipv6(),
                                     pkt.tcp(),
                                     pkt.length(),
                                     pkt.l4length(),
                                     pkt.timestamp());
                } else if (pkt.is_udp()) {
                  statistics.process(pkt.ipv6(),
                                     pkt.udp(),
                                     pkt.length(),
                                     pkt.l4length(),
                                     pkt.timestamp());
                }
              }
            }

            // End of file?
            if (analyzer.feof()) {
              printf("==================== End of file ====================\n");

              // Sleep interval.
              static constexpr const useconds_t sleep_interval = 500 * 1000;

              usleep(sleep_interval);
            } else if (analyzer.ferror()) {
              fprintf(stderr, "Error reading from file.\n");
              break;
            }
          } while (running);

          // Print statistics.
          statistics.print();

          return 0;
        } else {
          fprintf(stderr,
                  "Error opening CSV file '%s' for writing.\n",
                  argv[3]);
        }
      } else {
        fprintf(stderr, "Error opening PCAP file '%s' for reading.\n", argv[1]);
      }
    }
  } else {
    fprintf(stderr, "Usage: %s <directory> <pcap-file> <csv-file>\n", argv[0]);
  }

  return -1;
}

void signal_handler(int nsig)
{
  printf("Received signal %d.\n", nsig);

  running = false;
}
