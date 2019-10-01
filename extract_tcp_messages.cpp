#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include "pcap/ip/tcp/connection/analyzer.h"

int main(int argc, const char** argv)
{
  if (argc == 3) {
    struct stat sbuf;
    if ((stat(argv[2], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
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
          do {
            it.client_message(analyzer, argv[2]);
            it.server_message(analyzer, argv[2]);
          } while (conn_analyzer.next(it));
        } else {
          printf("No connections.\n");
        }

        return 0;
      } else {
        fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[1]);
      }
    } else {
      fprintf(stderr, "'%s' doesn't exist or is not a directory.\n", argv[2]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename> <directory>\n", argv[0]);
  }

  return -1;
}
