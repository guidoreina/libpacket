#include <stdlib.h>
#include <stdio.h>
#include "pcap/reader.h"

int main(int argc, const char** argv)
{
  if (argc == 2) {
    pcap::reader reader;

    // Open PCAP file.
    if (reader.open(argv[1])) {
      pcap::packet pkt;

      if (reader.begin(pkt)) {
        size_t count = 0;
        size_t total = 0;

        do {
          count++;
          total += pkt.length();
        } while (reader.next(pkt));

        printf("# packets: %zu\n", count);
        printf("%zu bytes\n", total);
        printf("%zu bytes per packet (average)\n", total / count);
      } else {
        printf("No packets.\n");
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
